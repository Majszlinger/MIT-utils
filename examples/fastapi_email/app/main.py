"""FastAPI reference app for Dimail usage through mit_utils.email."""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from fastapi import Depends, FastAPI, HTTPException, Path, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from mit_utils.email import (
    DimailAPIError,
    DimailClient,
    DimailConfigError,
    GraphAPIError,
    GraphConfigError,
    GraphEmailClient,
)

from .settings import Settings, SettingsError, get_settings


app = FastAPI(
    title="MIT Utils Email Reference",
    version="1.0.0",
    description="Reference FastAPI app for using mit_utils.email with Dimail and Microsoft Graph.",
)


class ProviderResponse(BaseModel):
    ok: bool = True
    provider: str
    payload: Any


class HealthResponse(BaseModel):
    ok: bool
    service: str
    dimail_configured: bool
    dimail_host: Optional[str]
    graph_configured: bool
    graph_base_url: str


class SendEmailRequest(BaseModel):
    to: str = Field(..., min_length=1)
    subject: str = Field(..., min_length=1)
    html_message: str = Field(..., min_length=1)
    text_message: str = ""


class GraphSendEmailRequest(BaseModel):
    to_recipients: List[str] = Field(..., min_length=1)
    subject: str = Field(..., min_length=1)
    body: str = Field(..., min_length=1)
    body_content_type: Literal["Text", "HTML"] = "Text"
    save_to_sent_items: bool = True
    cc_recipients: Optional[List[str]] = None
    bcc_recipients: Optional[List[str]] = None


class SubscribeRequest(BaseModel):
    email: str = Field(..., min_length=1)
    name: str = ""
    activated: bool = True
    force_name_change: bool = False


class UnsubscribeRequest(BaseModel):
    email: str = Field(..., min_length=1)


class CreateListRequest(BaseModel):
    name: str = Field(..., min_length=1)


class NewsletterRequest(BaseModel):
    subject: str = Field(..., min_length=1)
    html_message: str = Field(..., min_length=1)
    text_message: str = ""


class SendNewsletterRequest(BaseModel):
    start: int = Field(default=0, ge=0)


class CreateCampaignRequest(BaseModel):
    name: str = Field(..., min_length=1)


class CampaignListsRequest(BaseModel):
    list_ids: List[str] = Field(..., min_length=1)


class LoginTokenRequest(BaseModel):
    rkey: str = Field(..., min_length=1)


def _provider_response(payload: Any, provider: str = "dimail") -> ProviderResponse:
    return ProviderResponse(provider=provider, payload=payload)


def _safe_dimail_error(error: DimailAPIError) -> HTTPException:
    detail: Dict[str, Any] = {"message": str(error)}
    if error.status_code is not None:
        detail["status_code"] = error.status_code
    if error.raw_body or error.payload is None:
        detail["raw_body"] = error.raw_body[:1000]
        detail["raw_body_length"] = len(error.raw_body)
    if error.payload is not None:
        detail["payload"] = error.payload
    return HTTPException(status_code=502, detail=detail)


def _safe_graph_error(error: GraphAPIError) -> HTTPException:
    detail: Dict[str, Any] = {"message": str(error)}
    if error.status_code is not None:
        detail["status_code"] = error.status_code
    if error.response_text:
        detail["response_text"] = error.response_text[:1000]
        detail["response_text_length"] = len(error.response_text)
    if error.payload is not None:
        detail["payload"] = error.payload
    return HTTPException(status_code=502, detail=detail)


def _run_dimail_call(call) -> ProviderResponse:
    try:
        payload = call()
    except DimailAPIError as error:
        raise _safe_dimail_error(error) from error
    return _provider_response(payload)


def _run_graph_call(call) -> ProviderResponse:
    try:
        call()
    except GraphAPIError as error:
        raise _safe_graph_error(error) from error
    return _provider_response({"accepted": True}, provider="graph")


def get_dimail_client(settings: Settings = Depends(get_settings)) -> DimailClient:
    if not settings.has_dimail_api_key:
        raise DimailConfigError("DIMAIL_API_KEY is required.")

    return DimailClient(
        api_key=settings.dimail_api_key.get_secret_value(),
        host=settings.dimail_host,
        timeout=settings.dimail_timeout,
    )


def get_graph_client(settings: Settings = Depends(get_settings)) -> GraphEmailClient:
    if not settings.has_graph_config:
        raise GraphConfigError(
            "MS_GRAPH_TENANT_ID, MS_GRAPH_CLIENT_ID, MS_GRAPH_CLIENT_SECRET, and MS_GRAPH_SENDER_EMAIL are required."
        )

    return GraphEmailClient(
        tenant_id=settings.graph_tenant_id,
        client_id=settings.graph_client_id,
        client_secret=settings.graph_client_secret.get_secret_value(),
        timeout=settings.graph_timeout,
        graph_base_url=settings.graph_base_url,
    )


@app.exception_handler(DimailConfigError)
def handle_dimail_config_error(_, error: DimailConfigError):
    return JSONResponse(status_code=500, content={"detail": str(error)})


@app.exception_handler(GraphConfigError)
def handle_graph_config_error(_, error: GraphConfigError):
    return JSONResponse(status_code=500, content={"detail": str(error)})


@app.exception_handler(SettingsError)
def handle_settings_error(_, error: SettingsError):
    return JSONResponse(status_code=500, content={"detail": str(error)})


@app.get("/health", response_model=HealthResponse, tags=["Health"])
def health(settings: Settings = Depends(get_settings)) -> HealthResponse:
    return HealthResponse(
        ok=True,
        service="mit-utils-email-reference",
        dimail_configured=settings.has_dimail_api_key,
        dimail_host=settings.dimail_host,
        graph_configured=settings.has_graph_config,
        graph_base_url=settings.graph_base_url,
    )


@app.post(
    "/graph/send",
    response_model=ProviderResponse,
    tags=["Microsoft Graph Email"],
    summary="Send email with Microsoft Graph",
    description="Sends an email through Microsoft Graph using app credentials from environment variables.",
)
def send_graph_email(
    request: GraphSendEmailRequest,
    settings: Settings = Depends(get_settings),
    client: GraphEmailClient = Depends(get_graph_client),
) -> ProviderResponse:
    return _run_graph_call(
        lambda: client.send_email(
            sender_email=settings.graph_sender_email,
            to_recipients=request.to_recipients,
            subject=request.subject,
            body=request.body,
            body_content_type=request.body_content_type,
            save_to_sent_items=request.save_to_sent_items,
            cc_recipients=request.cc_recipients,
            bcc_recipients=request.bcc_recipients,
        )
    )


@app.post(
    "/dimail/send",
    response_model=ProviderResponse,
    tags=["Dimail Email"],
    summary="Send one email",
    description="Queues a one-off Dimail email. For bulk newsletter sends, use lists, campaigns, and newsletters.",
)
def send_dimail_email(
    request: SendEmailRequest,
    client: DimailClient = Depends(get_dimail_client),
) -> ProviderResponse:
    try:
        payload = client.send_email(
            request.to,
            request.subject,
            request.html_message,
            text_message=request.text_message,
        )
    except DimailAPIError as error:
        raise _safe_dimail_error(error) from error
    return _provider_response(payload)


@app.get(
    "/dimail/status/{send_id}",
    response_model=ProviderResponse,
    tags=["Dimail Email"],
    summary="Check one-off email status",
)
def get_dimail_status(
    send_id: str = Path(..., min_length=1),
    client: DimailClient = Depends(get_dimail_client),
) -> ProviderResponse:
    try:
        payload = client.check_email_status(send_id)
    except DimailAPIError as error:
        raise _safe_dimail_error(error) from error
    return _provider_response(payload)


@app.get(
    "/dimail/lists",
    response_model=ProviderResponse,
    tags=["Dimail Lists"],
    summary="List subscriber lists",
)
def list_dimail_lists(client: DimailClient = Depends(get_dimail_client)) -> ProviderResponse:
    return _run_dimail_call(client.list_lists)


@app.post(
    "/dimail/lists",
    response_model=ProviderResponse,
    tags=["Dimail Lists"],
    summary="Create subscriber list",
)
def create_dimail_list(
    request: CreateListRequest,
    client: DimailClient = Depends(get_dimail_client),
) -> ProviderResponse:
    return _run_dimail_call(lambda: client.create_list(request.name))


@app.delete(
    "/dimail/lists/{list_id}",
    response_model=ProviderResponse,
    tags=["Dimail Lists"],
    summary="Remove subscriber list",
)
def remove_dimail_list(
    list_id: str = Path(..., min_length=1),
    client: DimailClient = Depends(get_dimail_client),
) -> ProviderResponse:
    return _run_dimail_call(lambda: client.remove_list(list_id))


@app.post(
    "/dimail/lists/{list_id}/subscribe",
    response_model=ProviderResponse,
    tags=["Dimail Lists"],
    summary="Subscribe email to list",
)
def subscribe_dimail_list(
    request: SubscribeRequest,
    list_id: str = Path(..., min_length=1),
    client: DimailClient = Depends(get_dimail_client),
) -> ProviderResponse:
    try:
        payload = client.subscribe(
            list_id,
            request.email,
            name=request.name,
            activated=request.activated,
            force_name_change=request.force_name_change,
        )
    except DimailAPIError as error:
        raise _safe_dimail_error(error) from error
    return _provider_response(payload)


@app.post(
    "/dimail/lists/{list_id}/unsubscribe",
    response_model=ProviderResponse,
    tags=["Dimail Lists"],
    summary="Unsubscribe email from list",
)
def unsubscribe_dimail_list(
    request: UnsubscribeRequest,
    list_id: str = Path(..., min_length=1),
    client: DimailClient = Depends(get_dimail_client),
) -> ProviderResponse:
    try:
        payload = client.unsubscribe(list_id, request.email)
    except DimailAPIError as error:
        raise _safe_dimail_error(error) from error
    return _provider_response(payload)


@app.get(
    "/dimail/newsletters",
    response_model=ProviderResponse,
    tags=["Dimail Newsletters"],
    summary="List newsletters",
)
def list_dimail_newsletters(client: DimailClient = Depends(get_dimail_client)) -> ProviderResponse:
    return _run_dimail_call(client.list_newsletters)


@app.post(
    "/dimail/newsletters",
    response_model=ProviderResponse,
    tags=["Dimail Newsletters"],
    summary="Create newsletter content",
)
def create_dimail_newsletter(
    request: NewsletterRequest,
    client: DimailClient = Depends(get_dimail_client),
) -> ProviderResponse:
    return _run_dimail_call(
        lambda: client.create_newsletter(
            request.subject,
            request.html_message,
            text_message=request.text_message,
        )
    )


@app.put(
    "/dimail/newsletters/{newsletter_id}",
    response_model=ProviderResponse,
    tags=["Dimail Newsletters"],
    summary="Update newsletter content",
)
def update_dimail_newsletter(
    request: NewsletterRequest,
    newsletter_id: str = Path(..., min_length=1),
    client: DimailClient = Depends(get_dimail_client),
) -> ProviderResponse:
    return _run_dimail_call(
        lambda: client.update_newsletter(
            newsletter_id,
            request.subject,
            request.html_message,
            text_message=request.text_message,
        )
    )


@app.post(
    "/dimail/newsletters/{newsletter_id}/send",
    response_model=ProviderResponse,
    tags=["Dimail Newsletters"],
    summary="Send newsletter",
    description="Sends or schedules a newsletter. Attach a campaign with list IDs before sending to define the audience.",
)
def send_dimail_newsletter(
    request: SendNewsletterRequest,
    newsletter_id: str = Path(..., min_length=1),
    client: DimailClient = Depends(get_dimail_client),
) -> ProviderResponse:
    return _run_dimail_call(lambda: client.send_newsletter(newsletter_id, start=request.start))


@app.get(
    "/dimail/newsletters/{newsletter_id}/statistics",
    response_model=ProviderResponse,
    tags=["Dimail Newsletters"],
    summary="Get newsletter statistics",
)
def get_dimail_statistics(
    newsletter_id: str = Path(..., min_length=1),
    statistics_type: int = Query(default=1, ge=1),
    client: DimailClient = Depends(get_dimail_client),
) -> ProviderResponse:
    return _run_dimail_call(lambda: client.get_statistics(newsletter_id, statistics_type=statistics_type))


@app.post(
    "/dimail/campaigns",
    response_model=ProviderResponse,
    tags=["Dimail Campaigns"],
    summary="Create campaign",
)
def create_dimail_campaign(
    request: CreateCampaignRequest,
    client: DimailClient = Depends(get_dimail_client),
) -> ProviderResponse:
    return _run_dimail_call(lambda: client.create_campaign(request.name))


@app.delete(
    "/dimail/campaigns/{campaign_id}",
    response_model=ProviderResponse,
    tags=["Dimail Campaigns"],
    summary="Remove campaign",
)
def remove_dimail_campaign(
    campaign_id: str = Path(..., min_length=1),
    client: DimailClient = Depends(get_dimail_client),
) -> ProviderResponse:
    return _run_dimail_call(lambda: client.remove_campaign(campaign_id))


@app.post(
    "/dimail/campaigns/{campaign_id}/lists",
    response_model=ProviderResponse,
    tags=["Dimail Campaigns"],
    summary="Attach subscriber lists to campaign",
    description="Assigns the list IDs that define the subscribers targeted by this campaign.",
)
def update_dimail_campaign_lists(
    request: CampaignListsRequest,
    campaign_id: str = Path(..., min_length=1),
    client: DimailClient = Depends(get_dimail_client),
) -> ProviderResponse:
    return _run_dimail_call(lambda: client.update_campaign_lists(campaign_id, request.list_ids))


@app.post(
    "/dimail/campaigns/{campaign_id}/newsletters/{newsletter_id}",
    response_model=ProviderResponse,
    tags=["Dimail Campaigns"],
    summary="Attach campaign to newsletter",
    description="Connects an existing campaign to an existing newsletter. The campaign should already have list IDs attached.",
)
def attach_dimail_campaign_to_newsletter(
    campaign_id: str = Path(..., min_length=1),
    newsletter_id: str = Path(..., min_length=1),
    client: DimailClient = Depends(get_dimail_client),
) -> ProviderResponse:
    return _run_dimail_call(
        lambda: client.attach_campaign_to_newsletter(campaign_id, newsletter_id)
    )


@app.post(
    "/dimail/login-token",
    response_model=ProviderResponse,
    tags=["Dimail Admin"],
    summary="Create remote login token",
)
def create_dimail_login_token(
    request: LoginTokenRequest,
    client: DimailClient = Depends(get_dimail_client),
) -> ProviderResponse:
    return _run_dimail_call(lambda: client.create_login_token(request.rkey))
