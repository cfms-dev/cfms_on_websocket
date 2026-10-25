import hashlib
from abc import abstractmethod
from typing import Annotated, Any, Self

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_ssh_public_key,
)
from pydantic import Field, model_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DatabaseSession

from include.database.models.auth import UserAuthPolicy, UserAuthPublicKey
from include.database.models.identity import User
from include.database.session import Session
from include.domains.access.permissions import Permissions
from include.domains.identity.auth.flows import AuthenticationFailure
from include.domains.identity.auth.registry import auth_registry
from include.domains.identity.auth.types import AuthChains, AuthPurpose
from include.domains.identity.commands.auth_policies import (
    AuthPolicyConflict,
    AuthPolicyUnavailable,
    ensure_authentication_available,
    remove_credential_from_auth_policies,
    replace_auth_policy,
)
from include.domains.identity.tokens import TokenPurpose
from include.transport.request_handler import (
    REQUEST_UNSET,
    Omittable,
    RequestDataModel,
    RequestHandler,
    Result,
)
lazy from include.domains.identity.types import RequestUserID
lazy from include.transport.connection import ConnectionHandler
lazy from include.types import JsonInteger, NonEmptyString

_Label = Annotated[str, Field(max_length=255)] | None


class _UserRequest(RequestDataModel):
    user_id: Omittable[RequestUserID] = REQUEST_UNSET


class _PolicyReplacement(RequestDataModel):
    purpose: Annotated[AuthPurpose, Field(strict=False)]
    expected_revision: Annotated[JsonInteger, Field(ge=0)]
    chains: AuthChains


class _SetPoliciesRequest(_UserRequest):
    policies: Annotated[list[_PolicyReplacement], Field(min_length=1, max_length=3)]

    @model_validator(mode="after")
    def unique_purposes(self) -> Self:
        if len({p.purpose for p in self.policies}) != len(self.policies):
            raise ValueError("Policy purposes must be unique")
        return self


class _RegisterPublicKeyRequest(_UserRequest):
    public_key: NonEmptyString
    label: _Label = None


class _PublicKeyRequest(_UserRequest):
    credential_id: NonEmptyString


class _UpdatePublicKeyRequest(_PublicKeyRequest):
    label: _Label


class _UserAuthenticationHandler[RequestT: _UserRequest](RequestHandler[RequestT]):
    """Own authorization, per-user write serialization, transactions and audit."""

    requires_auth = True
    write = True
    required_token_purpose = TokenPurpose.ESCALATION

    def handle(self, handler: ConnectionHandler, request: RequestT) -> Result:
        target_id = (
            request.user_id if request.user_id is not REQUEST_UNSET else handler.user_id
        )
        audit_data: dict[str, Any] = {}
        request_data = request.model_dump(mode="json", exclude_unset=True)
        if "policies" in request_data:
            audit_data["purposes"] = [p["purpose"] for p in request_data["policies"]]
        if "credential_id" in request_data:
            audit_data["credential_id"] = request_data["credential_id"]
        try:
            if handler.user_id is None or handler.token is None:
                raise AuthenticationFailure(401, "Authentication required")
            with Session.begin() as session:
                requester = session.get(User, handler.user_id)
                required = TokenPurpose.GENERAL
                if self.write:
                    required |= TokenPurpose.ESCALATION
                if requester is None or not requester.is_token_valid(
                    handler.token, purpose=handler.token.purpose
                ):
                    raise AuthenticationFailure(401, "Invalid authentication token")
                if not handler.token.has_purpose(required):
                    raise AuthenticationFailure(403, "Token purpose is insufficient")
                permissions = requester.all_permissions
                if self.write:
                    allowed = (
                        Permissions.SUPER_CONFIGURE_AUTH_METHODS in permissions
                        or (
                            target_id == requester.id
                            and Permissions.CONFIGURE_AUTH_METHODS in permissions
                        )
                    )
                else:
                    allowed = target_id == requester.id or (
                        Permissions.SUPER_LIST_USER_AUTH_METHODS in permissions
                    )
                if not allowed:
                    raise AuthenticationFailure(403, "Permission denied")
                user = session.get(
                    User,
                    target_id,
                    with_for_update=self.write,
                    populate_existing=self.write,
                )
                if user is None:
                    raise AuthenticationFailure(404, "User not found")
                if target_id == requester.id and not user.is_token_valid(
                    handler.token, purpose=required
                ):
                    raise AuthenticationFailure(401, "Invalid authentication token")
                audit_data["target_username"] = user.username
                data = self.perform(session, user, request)
                if "credential_id" in data:
                    audit_data["credential_id"] = data["credential_id"]
            code, message = 200, "Success"
        except AuthPolicyConflict:
            code, message, data = (
                409,
                "Authentication policy changed",
                {"reason": "revision_conflict"},
            )
        except AuthPolicyUnavailable as exc:
            code, message, data = (
                409,
                "Authentication would become unavailable",
                {"reason": exc.reason},
            )
        except AuthenticationFailure as exc:
            code, message, data = exc.code, exc.message, exc.data
        handler.conclude_request(code, data, message)
        return Result(
            code=code, target=str(target_id), data=audit_data, user_id=handler.user_id
        )

    @abstractmethod
    def perform(
        self, session: DatabaseSession, user: User, request: RequestT
    ) -> dict[str, Any]:
        pass


class RequestGetUserAuthenticationHandler(_UserAuthenticationHandler[_UserRequest]):
    request_model = _UserRequest
    write = False
    required_token_purpose = TokenPurpose.GENERAL
    rate_limit_cost = 2

    def perform(
        self, session: DatabaseSession, user: User, request: _UserRequest
    ) -> dict[str, Any]:
        policies = {}
        for purpose in AuthPurpose:
            policy = session.get(UserAuthPolicy, (user.id, purpose.value))
            policies[purpose.value] = {
                "revision": policy.revision if policy else 0,
                "chains": policy.chains if policy else [],
            }
        return {
            "user_id": str(user.id),
            "methods": auth_registry.get_supported_methods_metadata(),
            "credentials": [
                c.model_dump(mode="json")
                for c in auth_registry.list_user_credentials(session, user)
            ],
            "policies": policies,
        }


class RequestSetUserAuthPoliciesHandler(
    _UserAuthenticationHandler[_SetPoliciesRequest]
):
    request_model = _SetPoliciesRequest
    rate_limit_cost = 5

    def perform(
        self, session: DatabaseSession, user: User, request: _SetPoliciesRequest
    ) -> dict[str, Any]:
        for replacement in request.policies:
            previous = session.get(UserAuthPolicy, (user.id, replacement.purpose.value))
            if (previous.revision if previous else 0) != replacement.expected_revision:
                raise AuthPolicyConflict("Authentication policy changed")
            try:
                replace_auth_policy(
                    session,
                    user,
                    replacement.purpose,
                    replacement.model_dump(mode="json")["chains"],
                    expected_revision=replacement.expected_revision,
                )
            except AuthPolicyConflict:
                raise
            except ValueError as exc:
                raise AuthenticationFailure(
                    400, "Invalid authentication policy", {"reason": "invalid_policy"}
                ) from exc
        session.flush()
        ensure_authentication_available(session, user)
        return {
            "policies": {
                p.purpose.value: {
                    "revision": p.expected_revision + 1,
                    "chains": p.model_dump(mode="json")["chains"],
                }
                for p in request.policies
            }
        }


class RequestRegisterUserAuthPublicKeyHandler(
    _UserAuthenticationHandler[_RegisterPublicKeyRequest]
):
    request_model = _RegisterPublicKeyRequest
    rate_limit_cost = 5

    def perform(
        self, session: DatabaseSession, user: User, request: _RegisterPublicKeyRequest
    ) -> dict[str, Any]:
        try:
            public_key = load_ssh_public_key(request.public_key.encode("utf-8"))
        except (ValueError, UnsupportedAlgorithm) as exc:
            raise AuthenticationFailure(
                400, "Invalid OpenSSH public key", {"reason": "invalid_public_key"}
            ) from exc
        if not isinstance(
            public_key,
            (ed25519.Ed25519PublicKey, rsa.RSAPublicKey, ec.EllipticCurvePublicKey),
        ):
            raise AuthenticationFailure(
                400, "Unsupported public key type", {"reason": "unsupported_public_key"}
            )
        credential = UserAuthPublicKey(
            user_id=user.id,
            public_key_der=public_key.public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            ),
            fingerprint=hashlib.sha256(
                public_key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
            ).digest(),
            label=request.label,
        )
        try:
            with session.begin_nested():
                session.add(credential)
                session.flush()
        except IntegrityError as exc:
            raise AuthenticationFailure(
                409,
                "Public key is already registered",
                {"reason": "duplicate_public_key"},
            ) from exc
        return {
            "credential_id": credential.id,
            "fingerprint": credential.fingerprint.hex(),
            "label": credential.label,
        }


class RequestUpdateUserAuthPublicKeyHandler(
    _UserAuthenticationHandler[_UpdatePublicKeyRequest]
):
    request_model = _UpdatePublicKeyRequest
    rate_limit_cost = 2

    def perform(
        self, session: DatabaseSession, user: User, request: _UpdatePublicKeyRequest
    ) -> dict[str, Any]:
        credential = session.get(UserAuthPublicKey, request.credential_id)
        if credential is None or credential.user_id != user.id:
            raise AuthenticationFailure(404, "Public key not found")
        credential.label = request.label
        return {"credential_id": credential.id, "label": credential.label}


class RequestDeleteUserAuthPublicKeyHandler(
    _UserAuthenticationHandler[_PublicKeyRequest]
):
    request_model = _PublicKeyRequest
    rate_limit_cost = 3

    def perform(
        self, session: DatabaseSession, user: User, request: _PublicKeyRequest
    ) -> dict[str, Any]:
        credential = session.get(UserAuthPublicKey, request.credential_id)
        if credential is None or credential.user_id != user.id:
            raise AuthenticationFailure(404, "Public key not found")
        remove_credential_from_auth_policies(session, user, "publickey", credential.id)
        session.delete(credential)
        session.flush()
        ensure_authentication_available(session, user)
        return {"credential_id": request.credential_id}
