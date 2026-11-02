"""Instaladores de un solo uso.

El usuario genera un token (POST /hosts/enroll-token) y descarga un script que ya lleva
ese token adentro. El script baja el binario del agente, lo vincula (POST /hosts/enroll)
y lo deja corriendo como servicio. El token se valida igual que en /hosts/enroll;
el script se puede pedir varias veces mientras el token siga vigente: lo que lo consume
es la vinculación, no la descarga.
"""
import shlex
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import config
from app.core.database import get_db
from app.core.security import as_utc, hash_enroll_token
from app.models import User

router = APIRouter(prefix="/installers", tags=["installers"])

SH = """#!/usr/bin/env bash
# Instalador de PortAlert para Linux. Enlace de un solo uso: vence a los pocos minutos.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Ejecuta este instalador con sudo:  sudo bash $0" >&2
  exit 1
fi

SERVER=__SERVER__
TOKEN=__TOKEN__
URL=__URL__
SHA256=__SHA__
BIN=/usr/local/bin/portalert-agent

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
echo "Descargando el agente de PortAlert..."
curl -fsSL "$URL" -o "$tmp"
if [ -n "$SHA256" ]; then
  echo "$SHA256  $tmp" | sha256sum -c - >/dev/null || { echo "El archivo descargado no coincide con el hash esperado." >&2; exit 1; }
fi
install -m 0755 "$tmp" "$BIN"

mkdir -p /etc/portalert
export PORTALERT_CONFIG=/etc/portalert/config.json
"$BIN" enroll --server "$SERVER" --token "$TOKEN"

cat > /etc/systemd/system/portalert-agent.service <<'UNIT'
[Unit]
Description=PortAlert agent
After=network-online.target
Wants=network-online.target

[Service]
Environment=PORTALERT_CONFIG=/etc/portalert/config.json
ExecStart=/usr/local/bin/portalert-agent run
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now portalert-agent
echo "Listo. El agente quedó instalado y enviará su primer reporte en unos segundos."
"""

PS1 = """# Instalador de PortAlert para Windows. Enlace de un solo uso: vence a los pocos minutos.
# Ejecutar en PowerShell como administrador.
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Error 'Abre PowerShell como administrador y vuelve a ejecutar este instalador.'
}

$Server = __SERVER__
$Token  = __TOKEN__
$Url    = __URL__
$Sha256 = __SHA__
$Dir    = Join-Path $env:ProgramFiles 'PortAlert'
$Exe    = Join-Path $Dir 'portalert-agent.exe'
$Conf   = Join-Path $env:ProgramData 'PortAlert\\config.json'

New-Item -ItemType Directory -Force -Path $Dir | Out-Null
New-Item -ItemType Directory -Force -Path (Split-Path $Conf) | Out-Null
Write-Host 'Descargando el agente de PortAlert...'
Invoke-WebRequest -Uri $Url -OutFile $Exe -UseBasicParsing
if ($Sha256 -ne '') {
  if ((Get-FileHash $Exe -Algorithm SHA256).Hash.ToLower() -ne $Sha256) {
    Remove-Item $Exe -Force
    Write-Error 'El archivo descargado no coincide con el hash esperado.'
  }
}

[Environment]::SetEnvironmentVariable('PORTALERT_CONFIG', $Conf, 'Machine')
$env:PORTALERT_CONFIG = $Conf
& $Exe enroll --server $Server --token $Token
if ($LASTEXITCODE -ne 0) { Write-Error 'No se pudo vincular el equipo.' }

$action  = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument ('/c set "PORTALERT_CONFIG=' + $Conf + '" && "' + $Exe + '" run')
$trigger = New-ScheduledTaskTrigger -AtStartup
$user    = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName 'PortAlertAgent' -Action $action -Trigger $trigger -Principal $user -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName 'PortAlertAgent'
Write-Host 'Listo. El agente quedó instalado y enviará su primer reporte en unos segundos.'
"""


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _check_token(db: Session, token: str) -> None:
    user = db.scalar(select(User).where(User.enroll_token_hash == hash_enroll_token(token)))
    if (
        not user
        or user.enroll_used_at is not None
        or user.enroll_expires_at is None
        or as_utc(user.enroll_expires_at) <= datetime.now(timezone.utc)
    ):
        raise HTTPException(404, "El instalador venció o ya se usó")


def _server_url(request: Request) -> str:
    return config.PUBLIC_API_URL or str(request.base_url).rstrip("/")


def _render(template: str, quote, token: str, server: str, url: str, sha: str) -> str:
    return (
        template.replace("__SERVER__", quote(server))
        .replace("__TOKEN__", quote(token))
        .replace("__URL__", quote(url))
        .replace("__SHA__", quote(sha))
    )


def _respond(body: str, filename: str) -> PlainTextResponse:
    return PlainTextResponse(
        body,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


@router.get("/instalar-{token}.sh", response_class=PlainTextResponse)
def installer_linux(token: str, request: Request, db: Session = Depends(get_db)):
    _check_token(db, token)
    if not config.AGENT_DOWNLOAD_URL_LINUX:
        raise HTTPException(503, "El instalador para Linux no está disponible todavía")
    body = _render(SH, shlex.quote, token, _server_url(request), config.AGENT_DOWNLOAD_URL_LINUX, config.AGENT_SHA256_LINUX)
    return _respond(body, "instalar-portalert.sh")


@router.get("/instalar-{token}.ps1", response_class=PlainTextResponse)
def installer_windows(token: str, request: Request, db: Session = Depends(get_db)):
    _check_token(db, token)
    if not config.AGENT_DOWNLOAD_URL_WINDOWS:
        raise HTTPException(503, "El instalador para Windows no está disponible todavía")
    body = _render(PS1, _ps_quote, token, _server_url(request), config.AGENT_DOWNLOAD_URL_WINDOWS, config.AGENT_SHA256_WINDOWS)
    return _respond(body, "instalar-portalert.ps1")