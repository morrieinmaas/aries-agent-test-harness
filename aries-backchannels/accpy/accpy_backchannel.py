import asyncio
import functools
import json
import os
import random
import subprocess
import sys
import uuid
from timeit import default_timer
from time import sleep

from python.agent_backchannel import (
    AgentBackchannel,
    default_genesis_txns,
    RUN_MODE,
    START_TIMEOUT,
)
from python.utils import (
    require_indy,
    flatten,
    log_json,
    log_msg,
    log_timer,
    output_reader,
    prompt_loop,
)
from python.storage import (
    store_resource,
    get_resource,
    delete_resource,
    push_resource,
    pop_resource,
    pop_resource_latest,
)

import aries_cloudcontroller

# AriesController = aries_cloudcontroller.AriesAgentController
# AriesMulti = aries_cloudcontroller.AriesMultitenantController


class AccPyAgentBackchannel(AgentBackchannel):
    def __init__(
        self,
        ident: str,
        http_port: int,
        admin_port: int,
        genesis_data: str = None,
        params: dict = {},
    ):
        super().__init__(ident, http_port, admin_port, genesis_data, params)

        self.agent_controller = aries_cloudcontroller.AriesAgentController(
            admin_url=f"http://localhost:{http_port}", api_key=None, is_multitenant=True
        )
        # get aca-py version if available
        self.acapy_version = None
        try:
            with open("./acapy-version.txt", "r") as file:
                self.acapy_version = file.readline()
        except:
            # ignore errors
            pass

        # set the acapy AIP version, defaulting to AIP10
        self.aip_version = "AIP10"

        # Aca-py : RFC
        self.connectionStateTranslationDict = {
            "invitation": "invited",
            "request": "requested",
            "response": "responded",
            "active": "complete",
        }

        # Aca-py : RFC
        self.issueCredentialStateTranslationDict = {
            "proposal_sent": "proposal-sent",
            "proposal_received": "proposal-received",
            "offer_sent": "offer-sent",
            "offer_received": "offer-received",
            "request_sent": "request-sent",
            "request_received": "request-received",
            "credential_issued": "credential-issued",
            "credential_received": "credential-received",
            "credential_acked": "done",
        }

        # AATH API : Acapy Admin API
        self.issueCredentialv2OperationTranslationDict = {
            "send-proposal": "send-proposal",
            "send-offer": "send-offer",
            "send-request": "send-request",
            "issue": "issue",
            "store": "store",
        }

        # AATH API : Acapy Admin API
        self.proofv2OperationTranslationDict = {
            "create-send-connectionless-request": "create-request",
            "send-presentation": "send-presentation",
            "send-request": "send-request",
            "verify-presentation": "verify-presentation",
            "send-proposal": "send-proposal",
        }

        # AATH API : Acapy Admin API
        self.TopicTranslationDict = {
            "issue-credential": "/issue-credential/",
            "issue-credential-v2": "/issue-credential-2.0/",
            "proof-v2": "/present-proof-2.0/",
        }

        # Aca-py : RFC
        self.presentProofStateTranslationDict = {
            "request_sent": "request-sent",
            "request_received": "request-received",
            "proposal_sent": "proposal-sent",
            "proposal_received": "proposal-received",
            "presentation_sent": "presentation-sent",
            "presentation_received": "presentation-received",
            "reject_sent": "reject-sent",
            "verified": "done",
            "presentation_acked": "done",
        }

        # Aca-py : RFC
        self.didExchangeResponderStateTranslationDict = {
            "initial": "invitation-sent",
            "invitation": "invitation-received",
            "request": "request-received",
            "response": "response-sent",
            "?": "abandoned",
            "active": "completed",
        }

        # Aca-py : RFC
        self.didExchangeRequesterStateTranslationDict = {
            "initial": "invitation-sent",
            "invitation": "invitation-received",
            "request": "request-sent",
            "response": "response-received",
            "?": "abandoned",
            "active": "completed",
        }

    def get_acapy_version_as_float(self):
        # construct some number to compare to with > or < instead of listing out the version number
        # if it starts with zero strip it off
        # if it ends in alpha or RC (or "-<anything>"), change it to .1 or 1
        # strip all dots
        # Does that work if I'm testing 0.5.5.1 hot fix? Just strip off the .1 since there won't be a major change here.

        if not self.acapy_version or 0 == len(self.acapy_version):
            return 0.0

        descriptiveTrailer = "-"
        comparibleVersion = self.acapy_version
        if comparibleVersion.startswith("0"):
            comparibleVersion = comparibleVersion[len("0") :]
        if "." in comparibleVersion:
            stringParts = comparibleVersion.split(".")
            comparibleVersion = "".join(stringParts)
        if descriptiveTrailer in comparibleVersion:
            # This means its not an offical release and came from Master/Main
            # replace with a .1 so that the number is higher than an offical release
            comparibleVersion = comparibleVersion.split(descriptiveTrailer)[0] + ".1"

        #  Make it a number. At this point "0.5.5-RC" should be 55.1. "0.5.4" should be 54.
        return float(comparibleVersion)

    def get_agent_args(self):
        result = [
            ("--endpoint", self.endpoint),
            ("--label", self.label),
            # "--auto-ping-connection",
            # "--auto-accept-invites",
            # "--auto-accept-requests",
            # "--auto-respond-messages",
            ("--inbound-transport", "http", "0.0.0.0", str(self.http_port)),
            ("--outbound-transport", "http"),
            ("--admin", "0.0.0.0", str(self.admin_port)),
            "--admin-insecure-mode",
            "--public-invites",
            ("--wallet-type", self.wallet_type),
            ("--wallet-name", self.wallet_name),
            ("--wallet-key", self.wallet_key),
        ]

        if self.get_acapy_version_as_float() > 56:
            result.append(("--auto-provision", "--recreate-wallet"))

        if self.genesis_data:
            result.append(("--genesis-transactions", self.genesis_data))
        if self.seed:
            result.append(("--seed", self.seed))
        if self.storage_type:
            result.append(("--storage-type", self.storage_type))
        if self.postgres:
            result.extend(
                [
                    ("--wallet-storage-type", "postgres_storage"),
                    ("--wallet-storage-config", json.dumps(self.postgres_config)),
                    ("--wallet-storage-creds", json.dumps(self.postgres_creds)),
                ]
            )
        if self.webhook_url:
            result.append(("--webhook-url", self.webhook_url))

        # This code for Tails Server is included here because aca-py does not support the env var directly yet.
        # when it does (and there is talk of supporting YAML) then this code can be removed.
        if os.getenv("TAILS_SERVER_URL") is not None:
            # if the env var is set for tails server then use that.
            result.append(("--tails-server-base-url", os.getenv("TAILS_SERVER_URL")))
        else:
            # if the tails server env is not set use the gov.bc TEST tails server.
            result.append(
                (
                    "--tails-server-base-url",
                    "https://tails-server-test.pathfinder.gov.bc.ca",
                )
            )

        if AIP_CONFIG >= 20 or os.getenv("EMIT-NEW-DIDCOMM-PREFIX") is not None:
            # if the env var is set for tails server then use that.
            result.append(("--emit-new-didcomm-prefix"))

        if AIP_CONFIG >= 20 or os.getenv("EMIT-NEW-DIDCOMM-MIME-TYPE") is not None:
            # if the env var is set for tails server then use that.
            result.append(("--emit-new-didcomm-mime-type"))

        # This code for log level is included here because aca-py does not support the env var directly yet.
        # when it does (and there is talk of supporting YAML) then this code can be removed.
        if os.getenv("LOG_LEVEL") is not None:
            result.append(("--log-level", os.getenv("LOG_LEVEL")))

        # result.append(("--trace", "--trace-target", "log", "--trace-tag", "acapy.events", "--trace-label", "acapy",))

        # if self.extra_args:
        #    result.extend(self.extra_args)

        return result

    def agent_state_translation(self, topic, operation, data):
        # This method is used to translate the agent states passes back in the responses of operations into the states the
        # test harness expects. The test harness expects states to be as they are written in the Protocol's RFC.
        # the following is what the tests/rfc expect vs what aca-py communicates
        # Connection Protocol:
        # Tests/RFC         |   Aca-py
        # invited           |   invitation
        # requested         |   request
        # responded         |   response
        # complete          |   active
        #
        # Issue Credential Protocol:
        # Tests/RFC         |   Aca-py
        # proposal-sent     |   proposal_sent
        # proposal-received |   proposal_received
        # offer-sent        |   offer_sent
        # offer_received    |   offer_received
        # request-sent      |   request_sent
        # request-received  |   request_received
        # credential-issued |   issued
        # credential-received | credential_received
        # done              |   credential_acked
        #
        # Present Proof Protocol:
        # Tests/RFC         |   Aca-py

        resp_json = json.loads(data)
        # Check to see if state is in the json
        if "state" in resp_json:
            agent_state = resp_json["state"]

            # if "did_exchange" in topic:
            #     if "rfc23_state" in resp_json:
            #         rfc_state = resp_json["rfc23_state"]
            #     else:
            #         rfc_state = resp_json["connection"]["rfc23_state"]
            #     data = data.replace('"state"' + ": " + '"' + agent_state + '"', '"state"' + ": " + '"' + rfc_state + '"')
            # else:
            # Check the thier_role property in the data and set the calling method to swap states to the correct role for DID Exchange
            if "their_role" in data:
                # if resp_json["connection"]["their_role"] == "invitee":
                if "invitee" in data:
                    de_state_trans_method = (
                        self.didExchangeResponderStateTranslationDict
                    )
                elif "inviter" in data:
                    de_state_trans_method = (
                        self.didExchangeRequesterStateTranslationDict
                    )
            else:
                # make the trans method any one, since it doesn't matter. It's probably Out of Band.
                de_state_trans_method = self.didExchangeResponderStateTranslationDict

            if topic == "connection":
                # if the response contains invitation id, swap out the connection states for the did exchange states
                if "invitation_msg_id" in data:
                    data = data.replace(
                        '"state"' + ": " + '"' + agent_state + '"',
                        '"state"'
                        + ": "
                        + '"'
                        + de_state_trans_method[agent_state]
                        + '"',
                    )
                else:
                    data = data.replace(
                        agent_state, self.connectionStateTranslationDict[agent_state]
                    )
            elif topic == "issue-credential":
                data = data.replace(
                    agent_state, self.issueCredentialStateTranslationDict[agent_state]
                )
            elif topic == "proof":
                data = data.replace(
                    '"state"' + ": " + '"' + agent_state + '"',
                    '"state"'
                    + ": "
                    + '"'
                    + self.presentProofStateTranslationDict[agent_state]
                    + '"',
                )
            elif topic == "out-of-band":
                data = data.replace(
                    '"state"' + ": " + '"' + agent_state + '"',
                    '"state"' + ": " + '"' + de_state_trans_method[agent_state] + '"',
                )
            elif topic == "did-exchange":
                data = data.replace(
                    '"state"' + ": " + '"' + agent_state + '"',
                    '"state"' + ": " + '"' + de_state_trans_method[agent_state] + '"',
                )
        return data

    async def listen_webhooks(self, webhook_port: str):
        self.webhook_port = webhook_port
        self.agent_controller.init_webhook_server(
            webhook_host="localhost", webhook_port=self.webhook_port
        )
        # await self.agent_controller.listen_webhooks()

    async def make_agent_POST_request(
        self, op, rec_id=None, data=None, text=False, params=None
    ) -> (int, str):

        if op["topic"] == "connection":
            operation = op["operation"]
            if operation == "create-invitation":
                agent_operation = "/connections/" + operation

                (
                    resp_status,
                    resp_text,
                ) = await self.agent_controller.connections.create_invitation()

                # extract invitation from the agent's response
                invitation_resp = json.loads(resp_text)
                resp_text = json.dumps(invitation_resp)

                if resp_status == 200:
                    resp_text = self.agent_state_translation(
                        op["topic"], operation, resp_text
                    )
                return (resp_status, resp_text)

        #     elif operation == "receive-invitation":
        #         agent_operation = "/connections/" + operation

        #         (resp_status, resp_text) = await self.admin_POST(agent_operation, data=data)
        #         if resp_status == 200: resp_text = self.agent_state_translation(op["topic"], None, resp_text)
        #         return (resp_status, resp_text)

        #     elif (operation == "accept-invitation"
        #         or operation == "accept-request"
        #         or operation == "remove"
        #         or operation == "start-introduction"
        #         or operation == "send-ping"
        #     ):
        #         connection_id = rec_id
        #         agent_operation = "/connections/" + connection_id + "/" + operation
        #         log_msg('POST Request: ', agent_operation, data)

        #         (resp_status, resp_text) = await self.admin_POST(agent_operation, data)

        #         log_msg(resp_status, resp_text)
        #         if resp_status == 200: resp_text = self.agent_state_translation(op["topic"], None, resp_text)
        #         return (resp_status, resp_text)

        # elif op["topic"] == "schema":
        #     # POST operation is to create a new schema
        #     agent_operation = "/schemas"
        #     log_msg(agent_operation, data)

        #     (resp_status, resp_text) = await self.admin_POST(agent_operation, data)

        #     log_msg(resp_status, resp_text)
        #     resp_text = self.move_field_to_top_level(resp_text, "schema_id")
        #     return (resp_status, resp_text)

        # elif op["topic"] == "credential-definition":
        #     # POST operation is to create a new cred def
        #     agent_operation = "/credential-definitions"
        #     log_msg(agent_operation, data)

        #     (resp_status, resp_text) = await self.admin_POST(agent_operation, data)

        #     log_msg(resp_status, resp_text)
        #     resp_text = self.move_field_to_top_level(resp_text, "credential_definition_id")
        #     return (resp_status, resp_text)

        # elif op["topic"] == "issue-credential":
        #     operation = op["operation"]

        #     acapy_topic = "/issue-credential/"

        #     if rec_id is None:
        #         agent_operation = acapy_topic + operation
        #     else:
        #         if (operation == "send-offer"
        #             or operation == "send-request"
        #             or operation == "issue"
        #             or operation == "store"
        #         ):
        #             # swap thread id for cred ex id from the webhook
        #             cred_ex_id = await self.swap_thread_id_for_exchange_id(rec_id, "credential-msg", "credential_exchange_id")
        #             agent_operation = acapy_topic + "records/" + cred_ex_id + "/" + operation
        #         # Make Special provisions for revoke since it is passing multiple query params not just one id.
        #         elif (operation == "revoke"):
        #             cred_rev_id = rec_id
        #             rev_reg_id = data["rev_registry_id"]
        #             publish = data["publish_immediately"]
        #             agent_operation = acapy_topic + operation + "?cred_rev_id=" + cred_rev_id + "&rev_reg_id=" + rev_reg_id + "&publish=" + str(publish).lower()
        #             data = None
        #         else:
        #             agent_operation = acapy_topic + operation

        #     log_msg(agent_operation, data)

        #     (resp_status, resp_text) = await self.admin_POST(agent_operation, data)

        #     log_msg(resp_status, resp_text)
        #     if resp_status == 200 and self.aip_version != "AIP20": resp_text = self.agent_state_translation(op["topic"], None, resp_text)
        #     return (resp_status, resp_text)

        # # Handle issue credential v2 POST operations
        # elif op["topic"] == "issue-credential-v2":
        #     (resp_status, resp_text) = await self.handle_issue_credential_v2_POST(op, rec_id=rec_id, data=data)
        #     return (resp_status, resp_text)

        # # Handle issue credential v2 POST operations
        # elif op["topic"] == "proof-v2":
        #     (resp_status, resp_text) = await self.handle_proof_v2_POST(op, rec_id=rec_id, data=data)
        #     return (resp_status, resp_text)

        # elif op["topic"] == "revocation":
        #     #set the acapyversion to master since work to set it is not complete. Remove when master report proper version
        #     #self.acapy_version = "0.5.5-RC"
        #     operation = op["operation"]
        #     agent_operation, admin_data = await self.get_agent_operation_acapy_version_based(op["topic"], operation, rec_id, data)

        #     log_msg(agent_operation, admin_data)

        #     if admin_data is None:
        #         (resp_status, resp_text) = await self.admin_POST(agent_operation)
        #     else:
        #         (resp_status, resp_text) = await self.admin_POST(agent_operation, admin_data)

        #     log_msg(resp_status, resp_text)
        #     if resp_status == 200: resp_text = self.agent_state_translation(op["topic"], None, resp_text)
        #     return (resp_status, resp_text)

        # elif op["topic"] == "proof":
        #     operation = op["operation"]
        #     if operation == "create-send-connectionless-request":
        #         operation = "create-request"
        #     if rec_id is None:
        #         agent_operation = "/present-proof/" + operation
        #     else:
        #         if (operation == "send-presentation"
        #             or operation == "send-request"
        #             or operation == "verify-presentation"
        #             or operation == "remove"
        #         ):

        #             if (operation not in "send-presentation" or operation not in "send-request") and (data is None or "~service" not in data):
        #                 # swap thread id for pres ex id from the webhook
        #                 pres_ex_id = await self.swap_thread_id_for_exchange_id(rec_id, "presentation-msg", "presentation_exchange_id")
        #             else:
        #                 # swap the thread id for the pres ex id in the service decorator (this is a connectionless proof)
        #                 pres_ex_id = data["~service"]["recipientKeys"][0]
        #             agent_operation = "/present-proof/records/" + pres_ex_id + "/" + operation

        #         else:
        #             agent_operation = "/present-proof/" + operation

        #     log_msg(agent_operation, data)

        #     if data is not None:
        #         # Format the message data that came from the test, to what the Aca-py admin api expects.
        #         data = self.map_test_json_to_admin_api_json(op["topic"], operation, data)

        #     (resp_status, resp_text) = await self.admin_POST(agent_operation, data)

        #     log_msg(resp_status, resp_text)
        #     if resp_status == 200: resp_text = self.agent_state_translation(op["topic"], None, resp_text)
        #     return (resp_status, resp_text)

        # # Handle out of band POST operations
        # elif op["topic"] == "out-of-band":
        #     (resp_status, resp_text) = await self.handle_out_of_band_POST(op, data=data)
        #     return (resp_status, resp_text)

        # # Handle did exchange POST operations
        # elif op["topic"] == "did-exchange":
        #     (resp_status, resp_text) = await self.handle_did_exchange_POST(op, rec_id=rec_id, data=data)
        #     return (resp_status, resp_text)

        return (501, "501: Not Implemented\n\n".encode("utf8"))

    async def make_agent_GET_request(
        self, op, rec_id=None, text=False, params=None
    ) -> (int, str):

        if op["topic"] == "status":
            status = 200 if self.ACTIVE else 418
            status_msg = "Active" if self.ACTIVE else "Inactive"
            return (status, json.dumps({"status": status_msg}))

        if op["topic"] == "version":
            if self.acapy_version is not None:
                status = 200
                # status_msg = json.dumps({"version": self.acapy_version})
                status_msg = self.acapy_version
            else:
                status = 404
                # status_msg = json.dumps({"version": "not found"})
                status_msg = "not found"
            return (status, status_msg)

        elif op["topic"] == "connection":
            if rec_id:
                (resp_status, resp_text) = await self.agent_controller.get_connection(
                    connection_id=rec_id
                )
            else:
                (resp_status, resp_text) = await self.agent_controller.get_connections()

            log_msg("GET Request agent operation: ", agent_operation)

            if resp_status != 200:
                return (resp_status, resp_text)

            log_msg("GET Request response details: ", resp_status, resp_text)

            resp_json = json.loads(resp_text)
            if rec_id:
                connection_info = {
                    "connection_id": resp_json["connection_id"],
                    "state": resp_json["state"],
                    "connection": resp_json,
                }
                resp_text = json.dumps(connection_info)
            else:
                resp_json = resp_json["results"]
                connection_infos = []
                for connection in resp_json:
                    connection_info = {
                        "connection_id": connection["connection_id"],
                        "state": connection["state"],
                        "connection": connection,
                    }
                    connection_infos.append(connection_info)
                resp_text = json.dumps(connection_infos)
            # translate the state from that the agent gave to what the tests expect
            resp_text = self.agent_state_translation(op["topic"], None, resp_text)
            return (resp_status, resp_text)

        elif op["topic"] == "did":
            (
                resp_status,
                resp_text,
            ) = await self.agent_controller.wallet.get_public_did()
            if resp_status != 200:
                return (resp_status, resp_text)

            resp_json = json.loads(resp_text)
            did = resp_json["result"]

            resp_text = json.dumps(did)
            return (resp_status, resp_text)

        elif op["topic"] == "schema":
            (resp_status, resp_text) = await self.agent_controller.schema.get_by_id(
                schema_id=rec_id
            )
            if resp_status != 200:
                return (resp_status, resp_text)

            resp_json = json.loads(resp_text)
            schema = resp_json["schema"]

            resp_text = json.dumps(schema)
            return (resp_status, resp_text)

        elif op["topic"] == "credential-definition":
            (
                resp_status,
                resp_text,
            ) = await self.agent_controller.definitions.get_by_id(cred_def_id=rec_id)
            if resp_status != 200:
                return (resp_status, resp_text)

            resp_json = json.loads(resp_text)
            credential_definition = resp_json["credential_definition"]

            resp_text = json.dumps(credential_definition)
            return (resp_status, resp_text)

        elif op["topic"] == "issue-credential":
            # swap thread id for cred ex id from the webhook
            cred_ex_id = await self.swap_thread_id_for_exchange_id(
                rec_id, "credential-msg", "credential_exchange_id"
            )

            (
                resp_status,
                resp_text,
            ) = await self.agent_controller.issuer.get_record_by_id(
                cred_ex_id=cred_ex_id
            )
            if resp_status == 200:
                resp_text = self.agent_state_translation(op["topic"], None, resp_text)
            return (resp_status, resp_text)

        # elif op["topic"] == "issue-credential-v2":
        #     # swap thread id for cred ex id from the webhook
        #     cred_ex_id = await self.swap_thread_id_for_exchange_id(rec_id, "credential-msg", "cred_ex_id")
        #     agent_operation = self.TopicTranslationDict[op["topic"]] + "records/" + cred_ex_id

        #     (resp_status, resp_text) = await self.agent_controller.issuer_v2.get_record_by_id(cred_ex_id = cred_ex_id)
        #     resp_text = self.move_field_to_top_level(resp_text, "state")
        #     return (resp_status, resp_text)

        elif op["topic"] == "credential":
            operation = op["operation"]
            if operation == "revoked":
                (
                    resp_status,
                    resp_text,
                ) = await self.agent_controller.credentials.is_revoked(
                    credential_id=rec_id
                )
            else:
                (
                    resp_status,
                    resp_text,
                ) = await self.agent_controller.credentials.get_by_id(
                    credential_id=rec_id
                )

            (
                resp_status,
                resp_text,
            ) = await self.agent_controller.credentials.get_by_id(credential_id=rec_id)
            return (resp_status, resp_text)

        elif op["topic"] == "proof":
            # swap thread id for pres ex id from the webhook
            pres_ex_id = await self.swap_thread_id_for_exchange_id(
                rec_id, "presentation-msg", "presentation_exchange_id"
            )

            (
                resp_status,
                resp_text,
            ) = await self.agent_controller.proofs.get_record_by_id(
                pres_ex_id=pres_ex_id
            )
            if resp_status == 200:
                resp_text = self.agent_state_translation(op["topic"], None, resp_text)
            return (resp_status, resp_text)

        # elif op["topic"] == "proof-v2":
        #     # swap thread id for pres ex id from the webhook
        #     pres_ex_id = await self.swap_thread_id_for_exchange_id(rec_id, "presentation-msg", "pres_ex_id")
        #     agent_operation = self.TopicTranslationDict[op["topic"]] + "records/" + pres_ex_id

        #     (resp_status, resp_text) = await self.admin_GET(agent_operation)
        #     #if resp_status == 200: resp_text = self.agent_state_translation(op["topic"], None, resp_text)
        #     return (resp_status, resp_text)

        elif op["topic"] == "revocation":
            operation = op["operation"]
            (
                agent_operation,
                admin_data,
            ) = await self.get_agent_operation_acapy_version_based(
                op["topic"], operation, rec_id, data=None
            )

            # TODO determine how to test multiple endpoints here.
            (
                resp_status,
                resp_text,
            ) = await self.agent_controller.revocations.get_revocation_registry(rec_id)
            return (resp_status, resp_text)

        elif op["topic"] == "did-exchange":

            connection_id = rec_id
            agent_operation = "/connections/" + connection_id

            (resp_status, resp_text) = await self.admin_GET(agent_operation)
            if resp_status == 200:
                resp_text = self.agent_state_translation(op["topic"], None, resp_text)
            return (resp_status, resp_text)

        return (501, "501: Not Implemented\n\n".encode("utf8"))

    async def make_agent_GET_request_response(
        self, topic, rec_id=None, text=False, params=None
    ) -> (int, str):
        if topic == "connection" and rec_id:
            connection_msg = pop_resource(rec_id, "connection-msg")
            i = 0
            while connection_msg is None and i < MAX_TIMEOUT:
                sleep(1)
                connection_msg = pop_resource(rec_id, "connection-msg")
                i = i + 1

            resp_status = 200
            if connection_msg:
                resp_text = json.dumps(connection_msg)
            else:
                resp_text = "{}"

            return (resp_status, resp_text)

        if topic == "did-exchange" and rec_id:
            didexchange_msg = pop_resource(rec_id, "didexchange-msg")
            i = 0
            while didexchange_msg is None and i < MAX_TIMEOUT:
                sleep(1)
                didexchange_msg = pop_resource(rec_id, "didexchange-msg")
                i = i + 1

            resp_status = 200
            if didexchange_msg:
                resp_text = json.dumps(didexchange_msg)
                resp_text = self.agent_state_translation(topic, None, resp_text)
            else:
                resp_text = "{}"

            return (resp_status, resp_text)

        # Poping webhook messages wihtout an id is unusual. This code may be removed when issue 944 is fixed
        # see https://app.zenhub.com/workspaces/von---verifiable-organization-network-5adf53987ccbaa70597dbec0/issues/hyperledger/aries-cloudagent-python/944
        if topic == "did-exchange" and rec_id is None:
            didexchange_msg = pop_resource_latest("connection-msg")
            i = 0
            while didexchange_msg is None and i < MAX_TIMEOUT:
                sleep(1)
                didexchange_msg = pop_resource_latest("connection-msg")
                i = i + 1

            resp_status = 200
            if didexchange_msg:
                resp_text = json.dumps(didexchange_msg)
                resp_text = self.agent_state_translation(topic, None, resp_text)
            else:
                resp_text = "{}"

            return (resp_status, resp_text)

        elif topic == "issue-credential" and rec_id:
            credential_msg = pop_resource(rec_id, "credential-msg")
            i = 0
            while credential_msg is None and i < MAX_TIMEOUT:
                sleep(1)
                credential_msg = pop_resource(rec_id, "credential-msg")
                i = i + 1

            resp_status = 200
            if credential_msg:
                resp_text = json.dumps(credential_msg)
            else:
                resp_text = "{}"

            return (resp_status, resp_text)

        elif topic == "credential" and rec_id:
            credential_msg = pop_resource(rec_id, "credential-msg")
            i = 0
            while credential_msg is None and i < MAX_TIMEOUT:
                sleep(1)
                credential_msg = pop_resource(rec_id, "credential-msg")
                i = i + 1

            resp_status = 200
            if credential_msg:
                resp_text = json.dumps(credential_msg)
            else:
                resp_text = "{}"

            return (resp_status, resp_text)

        elif topic == "proof" and rec_id:
            presentation_msg = pop_resource(rec_id, "presentation-msg")
            i = 0
            while presentation_msg is None and i < MAX_TIMEOUT:
                sleep(1)
                presentation_msg = pop_resource(rec_id, "presentation-msg")
                i = i + 1

            resp_status = 200
            if presentation_msg:
                resp_text = json.dumps(presentation_msg)
                if resp_status == 200:
                    resp_text = self.agent_state_translation(topic, None, resp_text)
            else:
                resp_text = "{}"

            return (resp_status, resp_text)

        elif topic == "revocation-registry" and rec_id:
            revocation_msg = pop_resource(rec_id, "revocation-registry-msg")
            i = 0
            while revocation_msg is None and i < MAX_TIMEOUT:
                sleep(1)
                revocation_msg = pop_resource(rec_id, "revocation-registry-msg")
                i = i + 1

            resp_status = 200
            if revocation_msg:
                resp_text = json.dumps(revocation_msg)
            else:
                resp_text = "{}"

            return (resp_status, resp_text)

        return (501, "501: Not Implemented\n\n".encode("utf8"))

    def _process(self, args, env, loop):
        proc = subprocess.Popen(
            args,
            env=env,
            encoding="utf-8",
        )
        loop.run_in_executor(
            None,
            output_reader,
            proc.stdout,
            functools.partial(self.handle_output, source="stdout"),
        )
        loop.run_in_executor(
            None,
            output_reader,
            proc.stderr,
            functools.partial(self.handle_output, source="stderr"),
        )
        return proc

    def get_process_args(self, bin_path: str = None):
        # TODO aca-py needs to be in the path so no need to give it a cmd_path
        cmd_path = "aca-py"
        if bin_path is None:
            bin_path = DEFAULT_BIN_PATH
        if bin_path:
            cmd_path = os.path.join(bin_path, cmd_path)
        print("Location of ACA-Py: " + cmd_path)
        if self.get_acapy_version_as_float() > 56:
            return list(flatten(([cmd_path, "start"], self.get_agent_args())))
        else:
            return list(
                flatten((["python3", cmd_path, "start"], self.get_agent_args()))
            )

    async def detect_process(self):
        # text = None

        async def fetch_swagger(url: str, timeout: float):
            text = None
            start = default_timer()
            async with ClientSession(timeout=ClientTimeout(total=3.0)) as session:
                while default_timer() - start < timeout:
                    try:
                        async with session.get(url) as resp:
                            if resp.status == 200:
                                text = await resp.text()
                                break
                    except (ClientError, asyncio.TimeoutError):
                        pass
                    await asyncio.sleep(0.5)
            return text

        status_url = self.admin_url + "/status"
        status_text = await fetch_swagger(status_url, START_TIMEOUT)
        print("Agent running with admin url", self.admin_url)

        if not status_text:
            raise Exception(
                "Timed out waiting for agent process to start. "
                + f"Admin URL: {status_url}"
            )
        ok = False
        try:
            status = json.loads(status_text)
            ok = isinstance(status, dict) and "version" in status
            if ok:
                self.acapy_version = status["version"]
                print(
                    "ACA-py Backchannel running with ACA-py version:",
                    self.acapy_version,
                )
        except json.JSONDecodeError:
            pass
        if not ok:
            raise Exception(
                f"Unexpected response from agent process. Admin URL: {status_url}"
            )

    async def start_process(
        self, python_path: str = None, bin_path: str = None, wait: bool = True
    ):
        my_env = os.environ.copy()
        python_path = DEFAULT_PYTHON_PATH if python_path is None else python_path
        if python_path:
            my_env["PYTHONPATH"] = python_path

        agent_args = self.get_process_args(bin_path)

        # start agent sub-process
        self.log(f"Starting agent sub-process ...")
        self.log(f"agent starting with params: ")
        self.log(agent_args)
        loop = asyncio.get_event_loop()
        self.proc = await loop.run_in_executor(
            None, self._process, agent_args, my_env, loop
        )
        if wait:
            await asyncio.sleep(1.0)
            await self.detect_process()

    def _terminate(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=0.5)
                self.log(f"Exited with return code {self.proc.returncode}")
            except subprocess.TimeoutExpired:
                msg = "Process did not terminate in time"
                self.log(msg)
                raise Exception(msg)

    async def terminate(self):
        loop = asyncio.get_event_loop()
        if self.proc:
            await loop.run_in_executor(None, self._terminate)
        await self.client_session.close()
        if self.webhook_site:
            await self.webhook_site.stop()


async def main(start_port: int, show_timing: bool = False, interactive: bool = True):

    genesis = await default_genesis_txns()
    if not genesis:
        print("Error retrieving ledger genesis transactions")
        sys.exit(1)

    agent = None

    try:
        agent = AccPyAgentBackchannel(
            "aca-py." + AGENT_NAME, start_port + 1, start_port + 2, genesis_data=genesis
        )

        # start backchannel (common across all types of agents)
        await agent.listen_backchannel(start_port)

        # start aca-py agent sub-process and listen for web hooks
        await agent.listen_webhooks(start_port + 3)
        await agent.register_did()

        await agent.start_process()
        agent.activate()

        # now wait ...
        if interactive:
            async for option in prompt_loop("(X) Exit? [X] "):
                if option is None or option in "xX":
                    break
        else:
            print("Press Ctrl-C to exit ...")
            remaining_tasks = asyncio.Task.all_tasks()
            await asyncio.gather(*remaining_tasks)

    finally:
        terminated = True
        try:
            if agent:
                await agent.terminate()
        except Exception:
            LOGGER.exception("Error terminating agent:")
            terminated = False

    await asyncio.sleep(0.1)

    if not terminated:
        os._exit(1)


def str2bool(v):
    if isinstance(v, bool):
        return v
    if v.lower() in ("yes", "true", "t", "y", "1"):
        return True
    elif v.lower() in ("no", "false", "f", "n", "0"):
        return False
    else:
        raise argparse.ArgumentTypeError("Boolean value expected.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Runs a Faber demo agent.")
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=8020,
        metavar=("<port>"),
        help="Choose the starting port number to listen on",
    )
    parser.add_argument(
        "-i",
        "--interactive",
        type=str2bool,
        default=True,
        metavar=("<interactive>"),
        help="Start agent interactively",
    )
    args = parser.parse_args()

    require_indy()

    try:
        asyncio.get_event_loop().run_until_complete(
            main(start_port=args.port, interactive=args.interactive)
        )
    except KeyboardInterrupt:
        os._exit(1)
