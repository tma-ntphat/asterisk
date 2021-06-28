/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2013, Digium, Inc.
 *
 * Joshua Colp <jcolp@digium.com>
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*** MODULEINFO
	<depend>pjproject</depend>
	<depend>res_pjsip</depend>
	<depend>res_pjsip_session</depend>
	<support_level>core</support_level>
 ***/

#include "asterisk.h"

#include <pjsip.h>
#include <pjsip_ua.h>

#include "asterisk/res_pjsip.h"
#include "asterisk/res_pjsip_session.h"
#include "asterisk/module.h"
#include "asterisk/acl.h"

/*! URI parameter for original host/port */
#define AST_SIP_X_AST_ORIG_HOST "x-ast-orig-host"
#define AST_SIP_X_AST_ORIG_HOST_LEN 15

#define is_sip_uri(uri) \
	(PJSIP_URI_SCHEME_IS_SIP(uri) || PJSIP_URI_SCHEME_IS_SIPS(uri))

#define is_tel_uri(uri) \
	PJSIP_URI_SCHEME_IS_TEL(uri)

#define is_allowed_uri(uri) \
	(is_sip_uri(uri) || is_tel_uri(uri))

static void save_orig_contact_host(pjsip_rx_data *rdata, pjsip_sip_uri *uri)
{
	pjsip_param *x_orig_host;
	pj_str_t p_value;
#define COLON_LEN 1
#define MAX_PORT_LEN 5
    ast_log(LOG_DEBUG, "TMA - save_orig_contact_host - START");

	if (rdata->msg_info.msg->type != PJSIP_REQUEST_MSG ||
		rdata->msg_info.msg->line.req.method.id != PJSIP_REGISTER_METHOD) {
        ast_log(LOG_DEBUG, "TMA - save_orig_contact_host - END - 1");
		return;
	}

	ast_debug(1, "Saving contact '%.*s:%d'\n",
		(int)uri->host.slen, uri->host.ptr, uri->port);

	x_orig_host = PJ_POOL_ALLOC_T(rdata->tp_info.pool, pjsip_param);
	x_orig_host->name = pj_strdup3(rdata->tp_info.pool, AST_SIP_X_AST_ORIG_HOST);
	p_value.slen = pj_strlen(&uri->host) + COLON_LEN + MAX_PORT_LEN;
	p_value.ptr = (char*)pj_pool_alloc(rdata->tp_info.pool, p_value.slen + 1);
	p_value.slen = snprintf(p_value.ptr, p_value.slen + 1, "%.*s:%d", (int)uri->host.slen, uri->host.ptr, uri->port);
	pj_strassign(&x_orig_host->value, &p_value);
	pj_list_insert_before(&uri->other_param, x_orig_host);

    ast_log(LOG_DEBUG, "TMA - save_orig_contact_host - END");
	return;
}

static void rewrite_uri(pjsip_rx_data *rdata, pjsip_sip_uri *uri, pj_pool_t *pool)
{
    ast_log(LOG_DEBUG, "TMA - rewrite_uri - START");

	if (pj_strcmp2(&uri->host, rdata->pkt_info.src_name) != 0) {
		save_orig_contact_host(rdata, uri);
	}

	pj_strdup2(pool, &uri->host, rdata->pkt_info.src_name);
	uri->port = rdata->pkt_info.src_port;
	if (!strcasecmp("WSS", rdata->tp_info.transport->type_name)) {
		/* WSS is special, we don't want to overwrite the URI at all as it needs to be ws */
	} else if (strcasecmp("udp", rdata->tp_info.transport->type_name)) {
		uri->transport_param = pj_str(rdata->tp_info.transport->type_name);
	} else {
		uri->transport_param.slen = 0;
	}
    ast_log(LOG_DEBUG, "TMA - rewrite_uri - END");
}

/*
 * Update the Record-Route headers in the request or response and in the dialog
 * object if exists.
 *
 * When NAT is in use, the address of the next hop in the SIP may be incorrect.
 * To address this  asterisk uses two strategies in parallel:
 *  1. intercept the messages at the transaction level and rewrite the
 *     messages before arriving at the dialog layer
 *  2. after the application processing, update the dialog object with the
 *     correct information
 *
 * The first strategy has a limitation that the SIP message may not have all
 * the information required to determine if the next hop is in the route set
 * or in the contact. Causing risk that asterisk will update the Contact on
 * receipt of an in-dialog message despite there being a route set saved in
 * the dialog.
 *
 * The second strategy has a limitation that not all UAC layers have interfaces
 * available to invoke this module after dialog creation.  (pjsip_sesion does
 * but pjsip_pubsub does not), thus this strategy can't update the dialog in
 * all cases needed.
 *
 * The ideal solution would be to implement an "incomming_request" event
 * in pubsub module that can then pass the dialog object to this module
 * on SUBSCRIBE, this module then should add itself as a listener to the dialog
 * for the subsequent requests and responses & then be able to properly update
 * the dialog object for all required events.
 */

static int rewrite_route_set(pjsip_rx_data *rdata, pjsip_dialog *dlg)
{
	pjsip_rr_hdr *rr = NULL;
	pjsip_sip_uri *uri;
	int res = -1;
	int ignore_rr = 0;
	int pubsub = 0;
    ast_log(LOG_DEBUG, "TMA - rewrite_route_set - START");

	if (rdata->msg_info.msg->type == PJSIP_RESPONSE_MSG) {
		pjsip_hdr *iter;
		for (iter = rdata->msg_info.msg->hdr.prev; iter != &rdata->msg_info.msg->hdr; iter = iter->prev) {
			if (iter->type == PJSIP_H_RECORD_ROUTE) {
				rr = (pjsip_rr_hdr *)iter;
				break;
			}
		}
	} else if (pjsip_method_cmp(&rdata->msg_info.msg->line.req.method, &pjsip_register_method)) {
		rr = pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_RECORD_ROUTE, NULL);
	} else {
		/**
		 * Record-Route header has no meaning in REGISTER requests
		 * and should be ignored
		 */
		ignore_rr = 1;
	}

	if (!pjsip_method_cmp(&rdata->msg_info.cseq->method, &pjsip_subscribe_method) ||
		!pjsip_method_cmp(&rdata->msg_info.cseq->method, &pjsip_notify_method)) {
		/**
		 * There is currently no good way to get the dlg object for a pubsub dialog
		 * so we will just look at the rr & contact of the current message and
		 * hope for the best
		 */
		pubsub = 1;
	}

	if (rr) {
		uri = pjsip_uri_get_uri(&rr->name_addr);
		rewrite_uri(rdata, uri, rdata->tp_info.pool);
		res = 0;
	}

	if (dlg && !pj_list_empty(&dlg->route_set) && !dlg->route_set_frozen) {
		pjsip_routing_hdr *route = dlg->route_set.next;
		uri = pjsip_uri_get_uri(&route->name_addr);
		rewrite_uri(rdata, uri, dlg->pool);
		res = 0;
	}

	if (!dlg && !rr && !ignore_rr  && !pubsub && rdata->msg_info.to->tag.slen){
		/**
		 * Even if this message doesn't have any route headers
		 * the dialog may, so wait until a later invocation that
		 * has a dialog reference to make sure there isn't a
		 * previously saved routset in the dialog before deciding
		 * the contact needs to be modified
		 */
		res = 0;
	}

    ast_log(LOG_DEBUG, "TMA - rewrite_route_set - END");
	return res;
}

static int rewrite_contact(pjsip_rx_data *rdata, pjsip_dialog *dlg)
{
	pjsip_contact_hdr *contact;
    ast_log(LOG_DEBUG, "TMA - rewrite_contact - START");

	contact = pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_CONTACT, NULL);
    ast_log(LOG_DEBUG, "TMA - rewrite_contact - check uri scheme");
	if (contact && !contact->star && (PJSIP_URI_SCHEME_IS_SIP(contact->uri) || PJSIP_URI_SCHEME_IS_SIPS(contact->uri))) {
		pjsip_sip_uri *uri = pjsip_uri_get_uri(contact->uri);

		rewrite_uri(rdata, uri, rdata->tp_info.pool);

		if (dlg && pj_list_empty(&dlg->route_set) && (!dlg->remote.contact
			|| pjsip_uri_cmp(PJSIP_URI_IN_REQ_URI, dlg->remote.contact->uri, contact->uri))) {
			dlg->remote.contact = (pjsip_contact_hdr*)pjsip_hdr_clone(dlg->pool, contact);
			dlg->target = dlg->remote.contact->uri;
		}
        ast_log(LOG_DEBUG, "TMA - rewrite_contact - END - 1");
		return 0;
	}

    ast_log(LOG_DEBUG, "TMA - rewrite_contact - END");
	return -1;
}

static pj_bool_t handle_rx_message(struct ast_sip_endpoint *endpoint, pjsip_rx_data *rdata)
{
	pjsip_dialog *dlg = pjsip_rdata_get_dlg(rdata);
    ast_log(LOG_DEBUG, "TMA - handle_rx_message - START");

	if (!endpoint) {
        ast_log(LOG_DEBUG, "TMA - handle_rx_message - END - 1");
		return PJ_FALSE;
	}

	if (endpoint->nat.rewrite_contact) {
		/* rewrite_contact is intended to ensure we send requests/responses to
		 * a routeable address when NAT is involved. The URI that dictates where
		 * we send requests/responses can be determined either by Record-Route
		 * headers or by the Contact header if no Record-Route headers are present.
		 * We therefore will attempt to rewrite a Record-Route header first, and if
		 * none are present, we fall back to rewriting the Contact header instead.
		 */
		if (rewrite_route_set(rdata, dlg)) {
			rewrite_contact(rdata, dlg);
		}
	}

	if (endpoint->nat.force_rport) {
		rdata->msg_info.via->rport_param = rdata->pkt_info.src_port;
	}

    ast_log(LOG_DEBUG, "TMA - handle_rx_message - END");
	return PJ_FALSE;
}

static pj_bool_t nat_on_rx_message(pjsip_rx_data *rdata)
{
	pj_bool_t res;
	struct ast_sip_endpoint *endpoint;
    ast_debug(2, "TMA - nat_on_rx_message - START");

	endpoint = ast_pjsip_rdata_get_endpoint(rdata);
	res = handle_rx_message(endpoint, rdata);
	ao2_cleanup(endpoint);
    ast_log(LOG_DEBUG, "TMA - nat_on_rx_message - END");
	return res;
}

/*! \brief Structure which contains information about a transport */
struct request_transport_details {
	/*! \brief Type of transport */
	enum ast_transport type;
	/*! \brief Potential pointer to the transport itself, if UDP */
	pjsip_transport *transport;
	/*! \brief Potential pointer to the transport factory itself, if TCP/TLS */
	pjsip_tpfactory *factory;
	/*! \brief Local address for transport */
	pj_str_t local_address;
	/*! \brief Local port for transport */
	int local_port;
};

/*! \brief Callback function for finding the transport the request is going out on */
static int find_transport_state_in_use(void *obj, void *arg, int flags)
{
	struct ast_sip_transport_state *transport_state = obj;
	struct request_transport_details *details = arg;
    ast_log(LOG_DEBUG, "TMA - find_transport_state_in_use - START");

	/* If an explicit transport or factory matches then this is what is in use, if we are unavailable
	 * to compare based on that we make sure that the type is the same and the source IP address/port are the same
	 */
	if (transport_state && ((details->transport && details->transport == transport_state->transport) ||
		(details->factory && details->factory == transport_state->factory) ||
		((details->type == transport_state->type) && (transport_state->factory) &&
			!pj_strcmp(&transport_state->factory->addr_name.host, &details->local_address) &&
			transport_state->factory->addr_name.port == details->local_port))) {
        ast_log(LOG_DEBUG, "TMA - find_transport_state_in_use - END - 1");
		return CMP_MATCH;
	}

    ast_log(LOG_DEBUG, "TMA - find_transport_state_in_use - END");
	return 0;
}

/*! \brief Helper function which returns the SIP URI of a Contact header */
static pjsip_sip_uri *nat_get_contact_sip_uri(pjsip_tx_data *tdata)
{
	pjsip_contact_hdr *contact = pjsip_msg_find_hdr(tdata->msg, PJSIP_H_CONTACT, NULL);
    ast_log(LOG_DEBUG, "TMA - nat_get_contact_sip_uri - START");

    ast_log(LOG_DEBUG, "TMA - nat_get_contact_sip_uri - check uri scheme");
	if (!contact || (!PJSIP_URI_SCHEME_IS_SIP(contact->uri) && !PJSIP_URI_SCHEME_IS_SIPS(contact->uri))) {
        ast_log(LOG_DEBUG, "TMA - nat_get_contact_sip_uri - END - 1");
		return NULL;
	}

    ast_log(LOG_DEBUG, "TMA - nat_get_contact_sip_uri - END");
	return pjsip_uri_get_uri(contact->uri);
}

/*! \brief Structure which contains hook details */
struct nat_hook_details {
	/*! \brief Outgoing message itself */
	pjsip_tx_data *tdata;
	/*! \brief Chosen transport */
	struct ast_sip_transport *transport;
};

/*! \brief Callback function for invoking hooks */
static int nat_invoke_hook(void *obj, void *arg, int flags)
{
	struct ast_sip_nat_hook *hook = obj;
	struct nat_hook_details *details = arg;
    ast_log(LOG_DEBUG, "TMA - nat_invoke_hook - START");

	if (hook->outgoing_external_message) {
		hook->outgoing_external_message(details->tdata, details->transport);
	}

    ast_log(LOG_DEBUG, "TMA - nat_invoke_hook - END");
	return 0;
}

static void restore_orig_contact_host(pjsip_tx_data *tdata)
{
	pjsip_contact_hdr *contact;
	pj_str_t x_name = { AST_SIP_X_AST_ORIG_HOST, AST_SIP_X_AST_ORIG_HOST_LEN };
	pjsip_param *x_orig_host;
	pjsip_sip_uri *uri;
	pjsip_hdr *hdr;
    ast_log(LOG_DEBUG, "TMA - restore_orig_contact_host - START");

	if (tdata->msg->type == PJSIP_REQUEST_MSG) {
		if (is_allowed_uri(tdata->msg->line.req.uri)) {
			uri = pjsip_uri_get_uri(tdata->msg->line.req.uri);
			while ((x_orig_host = pjsip_param_find(&uri->other_param, &x_name))) {
				pj_list_erase(x_orig_host);
			}
		}
		for (hdr = tdata->msg->hdr.next; hdr != &tdata->msg->hdr; hdr = hdr->next) {
			if (hdr->type == PJSIP_H_TO) {
				if (is_allowed_uri(((pjsip_fromto_hdr *) hdr)->uri)) {
					uri = pjsip_uri_get_uri(((pjsip_fromto_hdr *) hdr)->uri);
					while ((x_orig_host = pjsip_param_find(&uri->other_param, &x_name))) {
						pj_list_erase(x_orig_host);
					}
				}
			}
		}
	}

	if (tdata->msg->type != PJSIP_RESPONSE_MSG) {
        ast_log(LOG_DEBUG, "TMA - restore_orig_contact_host - END - 1");
		return;
	}

	contact = pjsip_msg_find_hdr(tdata->msg, PJSIP_H_CONTACT, NULL);
	while (contact) {
		pjsip_sip_uri *contact_uri = pjsip_uri_get_uri(contact->uri);
		x_orig_host = pjsip_param_find(&contact_uri->other_param, &x_name);

		if (x_orig_host) {
			char host_port[x_orig_host->value.slen + 1];
			char *sep;

			ast_debug(1, "Restoring contact %.*s:%d  to %.*s\n", (int)contact_uri->host.slen,
				contact_uri->host.ptr, contact_uri->port,
				(int)x_orig_host->value.slen, x_orig_host->value.ptr);

			strncpy(host_port, x_orig_host->value.ptr, x_orig_host->value.slen);
			host_port[x_orig_host->value.slen] = '\0';
			sep = strchr(host_port, ':');
			if (sep) {
				*sep = '\0';
				sep++;
				pj_strdup2(tdata->pool, &contact_uri->host, host_port);
				contact_uri->port = strtol(sep, NULL, 10);
			}
			pj_list_erase(x_orig_host);
		}
		contact = pjsip_msg_find_hdr(tdata->msg, PJSIP_H_CONTACT, contact->next);
	}
    ast_log(LOG_DEBUG, "TMA - restore_orig_contact_host - END");
}

static pj_status_t process_nat(pjsip_tx_data *tdata)
{
	RAII_VAR(struct ao2_container *, transport_states, NULL, ao2_cleanup);
	RAII_VAR(struct ast_sip_transport *, transport, NULL, ao2_cleanup);
	RAII_VAR(struct ast_sip_transport_state *, transport_state, NULL, ao2_cleanup);
	struct request_transport_details details = { 0, };
	pjsip_via_hdr *via = NULL;
	struct ast_sockaddr addr = { { 0, } };
	pjsip_sip_uri *uri = NULL;
	RAII_VAR(struct ao2_container *, hooks, NULL, ao2_cleanup);
    ast_log(LOG_DEBUG, "TMA - process_nat - START");

	/* If a transport selector is in use we know the transport or factory, so explicitly find it */
	if (tdata->tp_sel.type == PJSIP_TPSELECTOR_TRANSPORT) {
		details.transport = tdata->tp_sel.u.transport;
	} else if (tdata->tp_sel.type == PJSIP_TPSELECTOR_LISTENER) {
		details.factory = tdata->tp_sel.u.listener;
	} else if (tdata->tp_info.transport->key.type == PJSIP_TRANSPORT_UDP || tdata->tp_info.transport->key.type == PJSIP_TRANSPORT_UDP6) {
		/* Connectionless uses the same transport for all requests */
		details.type = AST_TRANSPORT_UDP;
		details.transport = tdata->tp_info.transport;
	} else {
		if (tdata->tp_info.transport->key.type == PJSIP_TRANSPORT_TCP) {
			details.type = AST_TRANSPORT_TCP;
		} else if (tdata->tp_info.transport->key.type == PJSIP_TRANSPORT_TLS) {
			details.type = AST_TRANSPORT_TLS;
		} else {
			/* Unknown transport type, we can't map and thus can't apply NAT changes */
            ast_log(LOG_DEBUG, "TMA - process_nat - END - 1");
			return PJ_SUCCESS;
		}

		if ((uri = nat_get_contact_sip_uri(tdata))) {
			details.local_address = uri->host;
			details.local_port = uri->port;
		} else if ((tdata->msg->type == PJSIP_REQUEST_MSG) &&
			(via = pjsip_msg_find_hdr(tdata->msg, PJSIP_H_VIA, NULL))) {
			details.local_address = via->sent_by.host;
			details.local_port = via->sent_by.port;
		} else {
            ast_log(LOG_DEBUG, "TMA - process_nat - END - 2");
			return PJ_SUCCESS;
		}

		if (!details.local_port) {
			details.local_port = (details.type == AST_TRANSPORT_TLS) ? 5061 : 5060;
		}
	}

	if (!(transport_states = ast_sip_get_transport_states())) {
        ast_log(LOG_DEBUG, "TMA - process_nat - END - 3");
		return PJ_SUCCESS;
	}

	if (!(transport_state = ao2_callback(transport_states, 0, find_transport_state_in_use, &details))) {
        ast_log(LOG_DEBUG, "TMA - process_nat - END - 4");
		return PJ_SUCCESS;
	}

	if (!(transport = ast_sorcery_retrieve_by_id(ast_sip_get_sorcery(), "transport", transport_state->id))) {
        ast_log(LOG_DEBUG, "TMA - process_nat - END - 5");
		return PJ_SUCCESS;
	}

	if (transport_state->localnet) {
		ast_sockaddr_parse(&addr, tdata->tp_info.dst_name, PARSE_PORT_FORBID);
		ast_sockaddr_set_port(&addr, tdata->tp_info.dst_port);

		/* See if where we are sending this request is local or not, and if not that we can get a Contact URI to modify */
		if (ast_sip_transport_is_local(transport_state, &addr)) {
			ast_debug(5, "Request is being sent to local address, skipping NAT manipulation\n");
            ast_log(LOG_DEBUG, "TMA - process_nat - END - 6");
			return PJ_SUCCESS;
		}
	}

	if (!ast_sockaddr_isnull(&transport_state->external_signaling_address)) {
		pjsip_cseq_hdr *cseq = PJSIP_MSG_CSEQ_HDR(tdata->msg);

		/* Update the Contact header with the external address. We only do this if
		 * a CSeq is not present (which should not happen - but we are extra safe),
		 * if a request is being sent, or if a response is sent that is not a response
		 * to a REGISTER. We specifically don't do this for a response to a REGISTER
		 * as the Contact headers would contain the registered Contacts, and not our
		 * own Contact.
		 */
		if (!cseq || tdata->msg->type == PJSIP_REQUEST_MSG ||
			pjsip_method_cmp(&cseq->method, &pjsip_register_method)) {
			/* We can only rewrite the URI when one is present */
			if (uri || (uri = nat_get_contact_sip_uri(tdata))) {
				pj_strdup2(tdata->pool, &uri->host, ast_sockaddr_stringify_host(&transport_state->external_signaling_address));
				if (transport->external_signaling_port) {
					uri->port = transport->external_signaling_port;
					ast_debug(4, "Re-wrote Contact URI port to %d\n", uri->port);
				}
			}
		}

		/* Update the via header if relevant */
		if ((tdata->msg->type == PJSIP_REQUEST_MSG) && (via || (via = pjsip_msg_find_hdr(tdata->msg, PJSIP_H_VIA, NULL)))) {
			pj_strdup2(tdata->pool, &via->sent_by.host, ast_sockaddr_stringify_host(&transport_state->external_signaling_address));
			if (transport->external_signaling_port) {
				via->sent_by.port = transport->external_signaling_port;
			}
		}
	}

	/* Invoke any additional hooks that may be registered */
	if ((hooks = ast_sorcery_retrieve_by_fields(ast_sip_get_sorcery(), "nat_hook", AST_RETRIEVE_FLAG_MULTIPLE | AST_RETRIEVE_FLAG_ALL, NULL))) {
		struct nat_hook_details hook_details = {
			.tdata = tdata,
			.transport = transport,
		};
		ao2_callback(hooks, 0, nat_invoke_hook, &hook_details);
	}

    ast_log(LOG_DEBUG, "TMA - process_nat - END");
	return PJ_SUCCESS;
}

static pj_status_t nat_on_tx_message(pjsip_tx_data *tdata) {
	pj_status_t rc;
    ast_debug(2, "TMA - nat_on_tx_message - START");

	rc = process_nat(tdata);
	restore_orig_contact_host(tdata);

    ast_debug(2, "TMA - nat_on_tx_message - END");
	return rc;
}


static pjsip_module nat_module = {
	.name = { "NAT", 3 },
	.id = -1,
	.priority = PJSIP_MOD_PRIORITY_TSX_LAYER - 2,
	.on_rx_request = nat_on_rx_message,
	.on_rx_response = nat_on_rx_message,
	.on_tx_request = nat_on_tx_message,
	.on_tx_response = nat_on_tx_message,
};

/*! \brief Function called when an INVITE goes out */
static int nat_incoming_invite_request(struct ast_sip_session *session, struct pjsip_rx_data *rdata)
{
    ast_log(LOG_DEBUG, "TMA - nat_incoming_invite_request - START");
	if (session->inv_session->state == PJSIP_INV_STATE_INCOMING) {
		pjsip_dlg_add_usage(session->inv_session->dlg, &nat_module, NULL);
	}

    ast_log(LOG_DEBUG, "TMA - nat_incoming_invite_request - END");
	return 0;
}

/*! \brief Function called when an INVITE response comes in */
static void nat_incoming_invite_response(struct ast_sip_session *session, struct pjsip_rx_data *rdata)
{
    ast_log(LOG_DEBUG, "TMA - nat_incoming_invite_response - START");
	handle_rx_message(session->endpoint, rdata);
    ast_log(LOG_DEBUG, "TMA - nat_incoming_invite_response - END");
}

/*! \brief Function called when an INVITE comes in */
static void nat_outgoing_invite_request(struct ast_sip_session *session, struct pjsip_tx_data *tdata)
{
    ast_log(LOG_DEBUG, "TMA - nat_outgoing_invite_request - START");
	if (session->inv_session->state == PJSIP_INV_STATE_NULL) {
		pjsip_dlg_add_usage(session->inv_session->dlg, &nat_module, NULL);
	}
    ast_log(LOG_DEBUG, "TMA - nat_outgoing_invite_request - END");
}

/*! \brief Supplement for adding NAT functionality to dialog */
static struct ast_sip_session_supplement nat_supplement = {
	.method = "INVITE",
	.priority = AST_SIP_SUPPLEMENT_PRIORITY_FIRST + 1,
	.incoming_request = nat_incoming_invite_request,
	.outgoing_request = nat_outgoing_invite_request,
	.incoming_response = nat_incoming_invite_response,
};


static int unload_module(void)
{
    ast_log(LOG_DEBUG, "TMA - unload_module - START");
	ast_sip_session_unregister_supplement(&nat_supplement);
	ast_sip_unregister_service(&nat_module);
    ast_log(LOG_DEBUG, "TMA - unload_module - END");
	return 0;
}

static int load_module(void)
{
    ast_log(LOG_DEBUG, "TMA - load_module - START");
	if (ast_sip_register_service(&nat_module)) {
		ast_log(LOG_ERROR, "Could not register NAT module for incoming and outgoing requests\n");
        ast_log(LOG_DEBUG, "TMA - load_module - END - 1");
		return AST_MODULE_LOAD_DECLINE;
	}

	ast_sip_session_register_supplement(&nat_supplement);

    ast_log(LOG_DEBUG, "TMA - load_module - END");
	return AST_MODULE_LOAD_SUCCESS;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "PJSIP NAT Support",
	.support_level = AST_MODULE_SUPPORT_CORE,
	.load = load_module,
	.unload = unload_module,
	.load_pri = AST_MODPRI_APP_DEPEND,
	.requires = "res_pjsip,res_pjsip_session",
);
