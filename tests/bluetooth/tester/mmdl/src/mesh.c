/* mesh.c - Bluetooth Mesh Tester */

/*
* Copyright (c) 2017 Intel Corporation
*
* SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
*/

#include <zephyr/bluetooth/bluetooth.h>

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <zephyr/bluetooth/mesh.h>
#include <zephyr/bluetooth/mesh/access.h>
#include <zephyr/bluetooth/mesh/cfg.h>
#include <zephyr/settings/settings.h>
#include <zephyr/sys/byteorder.h>
#include <app_keys.h>
#include "access.h"

#define LOG_LEVEL CONFIG_BT_MESH_LOG_LEVEL
#include "zephyr/logging/log.h"
LOG_MODULE_REGISTER(bttester_mesh);
#include "mesh/testing.h"
#include "model_handler.h"
#include "bttester.h"

#define CONTROLLER_INDEX 0

/* Health server data */
extern uint8_t cur_faults[CUR_FAULTS_MAX];
extern uint8_t reg_faults[CUR_FAULTS_MAX * 2];
extern struct bt_mesh_model vnd_models[1];

/* Provision node data */
static uint8_t net_key[16];
static uint16_t net_key_idx;
static uint8_t flags;
static uint32_t iv_index;
static uint16_t addr;
static uint8_t dev_key[16];
static uint8_t input_size;

/* Configured provisioning data */
static uint8_t dev_uuid[16];
static uint8_t static_auth[16];

struct net_ctx net = {
	.local = BT_MESH_ADDR_UNASSIGNED,
	.dst = BT_MESH_ADDR_UNASSIGNED,
};

/* Address of the Node that bound AppKeys to our models (PTS). It is the
* destination for Client model messages. It is stored in settings because
* without reprovisioning PTS does not bind AppKeys again after a reboot.
*/
#define TESTER_PTS_ADDR_KEY "bttester/pts_addr"

uint16_t tester_pts_addr = BT_MESH_ADDR_UNASSIGNED;

static int tester_settings_set(const char *name, size_t len, settings_read_cb read_cb,
	void *cb_arg)
{
	const char *next;
	ssize_t rc;

	if (!settings_name_steq(name, "pts_addr", &next) || next) {
		return -ENOENT;
	}

	if (len != sizeof(tester_pts_addr)) {
		return -EINVAL;
	}

	rc = read_cb(cb_arg, &tester_pts_addr, sizeof(tester_pts_addr));

	return (rc < 0) ? (int)rc : 0;
}

SETTINGS_STATIC_HANDLER_DEFINE(bttester, "bttester", NULL, tester_settings_set, NULL, NULL);

static void tester_pts_addr_set(uint16_t pts_addr)
{
	if (tester_pts_addr == pts_addr) {
		return;
	}

	tester_pts_addr = pts_addr;

	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		if (pts_addr == BT_MESH_ADDR_UNASSIGNED) {
			(void)settings_delete(TESTER_PTS_ADDR_KEY);
		} else {
			(void)settings_save_one(TESTER_PTS_ADDR_KEY, &tester_pts_addr,
						sizeof(tester_pts_addr));
		}
	}
}

static void tester_net_ctx_restore(void)
{
	uint16_t primary = bt_mesh_primary_addr();

	if (primary == BT_MESH_ADDR_UNASSIGNED) {
		return;
	}

	addr = primary;
	net.local = primary;
	net.net_idx = 0;
}

static void tester_net_ctx_clear(void)
{
	net.local = BT_MESH_ADDR_UNASSIGNED;
	net.dst = BT_MESH_ADDR_UNASSIGNED;
	net.net_idx = 0;
}

/* Model state clean-up for the no-reprovisioning mode.
*
* Model states are stored as "bt/mesh/s/<id>/data[/<name>]" (SIG) and
* "bt/mesh/v/<id>/data[/<name>]" (vendor). Only these keys are deleted:
* keys, AppKey bindings, subscriptions and publications are kept, so PTS can
* continue without provisioning and configuration.
*
* Only at the start of a Test Case: AutoPTS registers the MMDL service
* (BTP_SERVICE_ID_MESH_MODEL) only in the Test Case pre-run. After an IUT
* reset inside a Test Case (autopts/wid/mmdl.py iut_reset(): WID 630, 631,
* 661, 663) GAP and MESH are registered again, and MESH_INIT,
* MESH_CONFIG_PROVISIONING and MESH_START are sent again, but not the MMDL
* service registration. So the states stored before the reset are loaded,
* as the Test Case expects.
*
* Done in MESH_START before settings_load(), so the mesh stack loads the
* models with their default states.
*/
#define MODEL_DATA_KEYS_MAX 64
#define MODEL_DATA_KEY_LEN  48

struct model_data_keys {
	size_t cnt;
	bool overflow;
	char names[MODEL_DATA_KEYS_MAX][MODEL_DATA_KEY_LEN];
};

static struct model_data_keys data_keys;

/* Set by the MMDL service registration, used by the next MESH_START. RAM
* only: an IUT reset clears it.
*/
static bool model_data_clear_req;

void tester_model_data_clear_request(void)
{
	model_data_clear_req = true;
}

static int model_data_key_collect(const char *key, size_t len, settings_read_cb read_cb,
				void *cb_arg, void *param)
{
	struct model_data_keys *keys = param;
	const char *field;
	int n;

	ARG_UNUSED(len);
	ARG_UNUSED(read_cb);
	ARG_UNUSED(cb_arg);

	/* key is relative to "bt/mesh": "s/<id>/<field>[/...]" (SIG) or
	* "v/<id>/<field>[/...]" (vendor).
	*/
	if (!key || (key[0] != 's' && key[0] != 'v') || key[1] != '/') {
		return 0;
	}

	field = strchr(key + 2, '/');
	if (!field || strncmp(field + 1, "data", 4) != 0 ||
		(field[5] != '\0' && field[5] != '/')) {
		return 0;
	}

	if (keys->cnt >= MODEL_DATA_KEYS_MAX) {
		keys->overflow = true;
		return 0;
	}

	n = snprintk(keys->names[keys->cnt], MODEL_DATA_KEY_LEN, "bt/mesh/%s", key);
	if (n < 0 || n >= MODEL_DATA_KEY_LEN) {
		keys->overflow = true;
		return 0;
	}

	keys->cnt++;

	return 0;
}

static int model_data_clear(void)
{
	int64_t start = k_uptime_get();
	int err;

	data_keys.cnt = 0;
	data_keys.overflow = false;

	/* One walk over "bt/mesh" for both SIG and vendor models: the walk
	* reads every stored key anyway, so a second subtree means a second
	* full walk.
	*/
	err = settings_load_subtree_direct("bt/mesh", model_data_key_collect, &data_keys);
	if (err) {
		LOG_ERR("Failed to read bt/mesh (err %d)", err);
		return err;
	}

	/* Delete after the walk: deleting inside the load callback is not safe. */
	for (size_t i = 0; i < data_keys.cnt; i++) {
		err = settings_delete(data_keys.names[i]);
		if (err) {
			LOG_ERR("Failed to delete %s (err %d)", data_keys.names[i], err);
			return err;
		}
	}

	if (data_keys.overflow) {
		LOG_ERR("Model data keys not all deleted, increase MODEL_DATA_KEYS_MAX");
		return -ENOMEM;
	}

	printk("Model data cleared: %u keys, %lld ms\n", (unsigned int)data_keys.cnt,
		k_uptime_get() - start);

	return 0;
}

static void supported_commands(uint8_t *data, uint16_t len)
{
	struct net_buf_simple *buf = NET_BUF_SIMPLE(BTP_DATA_MAX_SIZE);

	net_buf_simple_init(buf, 0);

	/* 1st octet */
	net_buf_simple_add_u8(buf, 0);
	tester_set_bit(buf->data, MESH_READ_SUPPORTED_COMMANDS);
	tester_set_bit(buf->data, MESH_CONFIG_PROVISIONING);
	tester_set_bit(buf->data, MESH_INIT);
	tester_set_bit(buf->data, MESH_RESET);
	tester_set_bit(buf->data, MESH_START);

	tester_send(BTP_SERVICE_ID_MESH, MESH_READ_SUPPORTED_COMMANDS,
			CONTROLLER_INDEX, buf->data, buf->len);
}

static void link_open(bt_mesh_prov_bearer_t bearer)
{
	struct mesh_prov_link_open_ev ev;

	LOG_DBG("bearer 0x%02x", bearer);

	switch (bearer) {
	case BT_MESH_PROV_ADV:
		ev.bearer = MESH_PROV_BEARER_PB_ADV;
		break;
	case BT_MESH_PROV_GATT:
		ev.bearer = MESH_PROV_BEARER_PB_GATT;
		break;
	default:
		LOG_ERR("Invalid bearer");

		return;
	}

	tester_send(BTP_SERVICE_ID_MESH, MESH_EV_PROV_LINK_OPEN,
			CONTROLLER_INDEX, (uint8_t *) &ev, sizeof(ev));
}

static void link_close(bt_mesh_prov_bearer_t bearer)
{
	struct mesh_prov_link_closed_ev ev;

	LOG_DBG("bearer 0x%02x", bearer);

	switch (bearer) {
	case BT_MESH_PROV_ADV:
		ev.bearer = MESH_PROV_BEARER_PB_ADV;
		break;
	case BT_MESH_PROV_GATT:
		ev.bearer = MESH_PROV_BEARER_PB_GATT;
		break;
	default:
		LOG_ERR("Invalid bearer");

		return;
	}

	tester_send(BTP_SERVICE_ID_MESH, MESH_EV_PROV_LINK_CLOSED,
			CONTROLLER_INDEX, (uint8_t *) &ev, sizeof(ev));
}

static int output_numeric(bt_mesh_output_action_t action, uint8_t *numeric, size_t size)
{
	struct mesh_out_number_action_ev ev;
	uint32_t number;

	if (size > sizeof(number)) {
		LOG_ERR("Unsupported size %zu", size);
		return -EINVAL;
	}

	number = sys_get_le32(numeric);

	LOG_DBG("action 0x%04x number 0x%08x", action, number);

	ev.action = sys_cpu_to_le16(action);
	ev.number = sys_cpu_to_le32(number);

	tester_send(BTP_SERVICE_ID_MESH, MESH_EV_OUT_NUMBER_ACTION,
			CONTROLLER_INDEX, (uint8_t *) &ev, sizeof(ev));

	return 0;
}

static int output_string(const char *str)
{
	struct mesh_out_string_action_ev *ev;
	struct net_buf_simple *buf = NET_BUF_SIMPLE(BTP_DATA_MAX_SIZE);

	LOG_DBG("str %s", str);

	net_buf_simple_init(buf, 0);

	ev = net_buf_simple_add(buf, sizeof(*ev));
	ev->string_len = strlen(str);

	net_buf_simple_add_mem(buf, str, ev->string_len);

	tester_send(BTP_SERVICE_ID_MESH, MESH_EV_OUT_STRING_ACTION,
			CONTROLLER_INDEX, buf->data, buf->len);

	return 0;
}

static int input(bt_mesh_input_action_t action, uint8_t size)
{
	struct mesh_in_action_ev ev;

	LOG_DBG("action 0x%04x number 0x%02x", action, size);

	input_size = size;

	ev.action = sys_cpu_to_le16(action);
	ev.size = size;

	tester_send(BTP_SERVICE_ID_MESH, MESH_EV_IN_ACTION, CONTROLLER_INDEX,
			(uint8_t *) &ev, sizeof(ev));

	return 0;
}

static void prov_complete(uint16_t net_idx, uint16_t elem_addr)
{
	LOG_DBG("net_idx 0x%04x addr 0x%04x", net_idx, elem_addr);

	addr = elem_addr;

	net.net_idx = net_idx,
	net.local = elem_addr;
	net.dst = elem_addr;

	tester_send(BTP_SERVICE_ID_MESH, MESH_EV_PROVISIONED, CONTROLLER_INDEX,
			NULL, 0);
}

static void prov_reset(void)
{
	int err;

	LOG_DBG("");

	err = bt_mesh_prov_enable(BT_MESH_PROV_ADV | BT_MESH_PROV_GATT);
	if (err && err != -EALREADY) {
		LOG_ERR("prov enable error %d", err);
	}
}

static const struct bt_mesh_comp *comp;

static struct bt_mesh_prov prov = {
	.uuid = dev_uuid,
	.static_val = static_auth,
	.static_val_len = sizeof(static_auth),
	.output_numeric = output_numeric,
	.output_string = output_string,
	.input = input,
	.link_open = link_open,
	.link_close = link_close,
	.complete = prov_complete,
	.reset = prov_reset,
};

static void config_prov(uint8_t *data, uint16_t len)
{
	const struct mesh_config_provisioning_cmd *cmd = (void *) data;

	LOG_DBG("");

	memcpy(dev_uuid, cmd->uuid, sizeof(dev_uuid));
	memcpy(static_auth, cmd->static_auth, sizeof(static_auth));

	prov.output_size = cmd->out_size;
	prov.output_actions = sys_le16_to_cpu(cmd->out_actions);
	prov.input_size = cmd->in_size;
	prov.input_actions = sys_le16_to_cpu(cmd->in_actions);

	tester_rsp(BTP_SERVICE_ID_MESH, MESH_CONFIG_PROVISIONING,
		CONTROLLER_INDEX, BTP_STATUS_SUCCESS);
}

static void init(uint8_t *data, uint16_t len)
{
	uint8_t status = BTP_STATUS_SUCCESS;
	int err;

	LOG_DBG("");

	comp = model_handler_init();
	err = bt_mesh_init(&prov, comp);
	if (err && err != -EALREADY) {
		status = BTP_STATUS_FAILED;
	}

	tester_rsp(BTP_SERVICE_ID_MESH, MESH_INIT, CONTROLLER_INDEX,
		status);
}

static void start(uint8_t *data, uint16_t len)
{
	uint8_t status = BTP_STATUS_SUCCESS;
	int err;

	LOG_DBG("");

	if (IS_ENABLED(CONFIG_BT_SETTINGS)) {
		/* Each Test Case starts with default model states. Not done after
		* an IUT reset inside a Test Case (no MMDL service registration)
		* and not if the node is already running (MESH_START sent again
		* without reboot).
		*/
		if (model_data_clear_req && !bt_mesh_is_provisioned() &&
			model_data_clear()) {
			status = BTP_STATUS_FAILED;
		}
		model_data_clear_req = false;

		printk("Loading stored settings\n");
		int64_t load_start = k_uptime_get();

		settings_load();
		printk("Settings loaded: %lld ms\n", k_uptime_get() - load_start);
	}

	/* Node already in a network (flash or current session): do not re-open PB-ADV. */
	if (!bt_mesh_is_provisioned()) {
		if (addr) {
			err = bt_mesh_provision(net_key, net_key_idx, flags, iv_index,
						addr, dev_key);
			if (err && err != -EALREADY) {
				status = BTP_STATUS_FAILED;
			}
		} else {
			err = bt_mesh_prov_enable(BT_MESH_PROV_ADV | BT_MESH_PROV_GATT);
			if (err && err != -EALREADY) {
				status = BTP_STATUS_FAILED;
			}
		}
	} else {
		tester_net_ctx_restore();
	}

	tester_rsp(BTP_SERVICE_ID_MESH, MESH_START, CONTROLLER_INDEX,
		status);
}

static void reset(uint8_t *data, uint16_t len)
{
	LOG_DBG("");

	addr = 0U;

	tester_net_ctx_clear();
	tester_pts_addr_set(BT_MESH_ADDR_UNASSIGNED);
	bt_mesh_reset();

	tester_rsp(BTP_SERVICE_ID_MESH, MESH_RESET, CONTROLLER_INDEX,
		BTP_STATUS_SUCCESS);
}

void tester_handle_mesh(uint8_t opcode, uint8_t index, uint8_t *data, uint16_t len)
{
	switch (opcode) {
	case MESH_READ_SUPPORTED_COMMANDS:
		supported_commands(data, len);
		break;
	case MESH_CONFIG_PROVISIONING:
		config_prov(data, len);
		break;
	case MESH_INIT:
		init(data, len);
		break;
	case MESH_START:
		start(data, len);
		break;
	case MESH_RESET:
		reset(data, len);
		break;
	default:
		tester_rsp(BTP_SERVICE_ID_MESH, opcode, index,
			BTP_STATUS_UNKNOWN_CMD);
		break;
	}
}

void net_recv_ev(uint8_t ttl, uint8_t ctl, uint16_t src, uint16_t dst, const void *payload,
		size_t payload_len)
{
	NET_BUF_SIMPLE_DEFINE(buf, UINT8_MAX);
	struct mesh_net_recv_ev *ev;

	LOG_DBG("ttl 0x%02x ctl 0x%02x src 0x%04x dst 0x%04x payload_len %zu",
		ttl, ctl, src, dst, payload_len);

	if (payload_len > net_buf_simple_tailroom(&buf)) {
		LOG_ERR("Payload size exceeds buffer size");
		return;
	}

	ev = net_buf_simple_add(&buf, sizeof(*ev));
	ev->ttl = ttl;
	ev->ctl = ctl;
	ev->src = sys_cpu_to_le16(src);
	ev->dst = sys_cpu_to_le16(dst);
	ev->payload_len = payload_len;
	net_buf_simple_add_mem(&buf, payload, payload_len);

	tester_send(BTP_SERVICE_ID_MESH, MESH_EV_NET_RECV, CONTROLLER_INDEX,
			buf.data, buf.len);
}

static void model_bound_cb(uint16_t addr, const struct bt_mesh_model *model,
			uint16_t key_idx)
{
	LOG_DBG("remote addr 0x%04x key_idx 0x%04x model %p",
		addr, key_idx, (void *)model);

	/* Do not touch model publication here: a server model with publication
	* set sends an extra status on every state change.
	*/
	tester_pts_addr_set(addr);
}

static void model_unbound_cb(uint16_t addr, const struct bt_mesh_model *model,
				uint16_t key_idx)
{
	LOG_DBG("remote addr 0x%04x key_idx 0x%04x model %p",
		addr, key_idx, (void *)model);
}

static void invalid_bearer_cb(uint8_t opcode)
{
	struct mesh_invalid_bearer_ev ev = {
		.opcode = opcode,
	};

	LOG_DBG("opcode 0x%02x", opcode);

	tester_send(BTP_SERVICE_ID_MESH, MESH_EV_INVALID_BEARER,
			CONTROLLER_INDEX, (uint8_t *) &ev, sizeof(ev));
}

static void incomp_timer_exp_cb(void)
{
	tester_send(BTP_SERVICE_ID_MESH, MESH_EV_INCOMP_TIMER_EXP,
			CONTROLLER_INDEX, NULL, 0);
}

static struct bt_mesh_test_cb mesh_test_cb = {
	.net_recv = net_recv_ev,
	.model_bound = model_bound_cb,
	.model_unbound = model_unbound_cb,
	.prov_invalid_bearer = invalid_bearer_cb,
	.trans_incomp_timer_exp = incomp_timer_exp_cb,
};

uint8_t tester_init_mesh(void)
{
	if (IS_ENABLED(CONFIG_BT_TESTING)) {
		bt_mesh_test_cb_register(&mesh_test_cb);
	}

	return BTP_STATUS_SUCCESS;
}

uint8_t tester_unregister_mesh(void)
{
	return BTP_STATUS_SUCCESS;
}