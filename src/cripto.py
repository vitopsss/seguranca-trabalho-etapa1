"""Operações criptográficas: SHA-256 e Ed25519 (biblioteca `cryptography`)."""

import hashlib
import os
import re

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

TAMANHO_ASSINATURA = 64
TAMANHO_MAXIMO_PEM = 64 * 1024


class ErroSeguranca(Exception):
    """Erro esperado, com mensagem própria para o usuário."""


def _abrir_leitura(caminho):
    if os.path.isdir(caminho):
        raise ErroSeguranca(f"o caminho é um diretório, não um arquivo: {caminho}")
    if os.path.exists(caminho) and not os.path.isfile(caminho):
        raise ErroSeguranca(f"o caminho não é um arquivo comum: {caminho}")
    try:
        return open(caminho, "rb")
    except FileNotFoundError:
        raise ErroSeguranca(f"arquivo não encontrado: {caminho}") from None
    except PermissionError:
        raise ErroSeguranca(f"sem permissão para ler: {caminho}") from None
    except (OSError, ValueError) as erro:
        raise ErroSeguranca(f"não foi possível ler '{caminho}': {erro}") from None


def _ler(caminho, limite=-1):
    with _abrir_leitura(caminho) as arquivo:
        return arquivo.read(limite)


def _criar_arquivo(caminho, dados, modo=0o644):
    """Cria um arquivo novo. Nunca sobrescreve um arquivo existente."""
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descritor = os.open(caminho, flags, modo)
    except FileExistsError:
        raise ErroSeguranca(
            f"o destino já existe e não será sobrescrito: {caminho}"
        ) from None
    except FileNotFoundError:
        raise ErroSeguranca(
            f"caminho inválido (o diretório existe?): {caminho}"
        ) from None
    except PermissionError:
        raise ErroSeguranca(f"sem permissão para gravar: {caminho}") from None
    except (OSError, ValueError) as erro:
        raise ErroSeguranca(f"não foi possível criar '{caminho}': {erro}") from None

    try:
        with os.fdopen(descritor, "wb") as arquivo:
            arquivo.write(dados)
    except OSError as erro:
        os.remove(caminho)  # não deixa arquivo pela metade
        raise ErroSeguranca(f"falha ao gravar '{caminho}': {erro}") from None


def gerar_chaves(caminho_privada, caminho_publica):
    """Gera um par Ed25519: privada em PKCS#8 e pública em SubjectPublicKeyInfo."""
    privada = Ed25519PrivateKey.generate()
    pem_privada = privada.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pem_publica = privada.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    _criar_arquivo(caminho_privada, pem_privada, 0o600)
    try:
        _criar_arquivo(caminho_publica, pem_publica)
    except ErroSeguranca:
        os.remove(caminho_privada)  # o par é criado por inteiro ou não é criado
        raise


def calcular_hash(caminho):
    """SHA-256 em hexadecimal minúsculo, lendo o arquivo em blocos."""
    resumo = hashlib.sha256()
    with _abrir_leitura(caminho) as arquivo:
        while bloco := arquivo.read(1024 * 1024):
            resumo.update(bloco)
    return resumo.hexdigest()


def normalizar_hash(referencia):
    if not re.fullmatch(r"[0-9a-fA-F]{64}", referencia):
        raise ErroSeguranca(
            "hash de referência inválido: são esperados 64 caracteres hexadecimais"
        )
    return referencia.lower()


def _carregar_privada(caminho):
    pem = _ler(caminho, TAMANHO_MAXIMO_PEM)
    try:
        chave = serialization.load_pem_private_key(pem, password=None)
    except TypeError:
        raise ErroSeguranca(
            f"chave privada protegida por senha não é suportada: {caminho}"
        ) from None
    except (ValueError, UnsupportedAlgorithm):
        raise ErroSeguranca(
            f"o arquivo não é uma chave privada PEM válida: {caminho}"
        ) from None
    if not isinstance(chave, Ed25519PrivateKey):
        raise ErroSeguranca(f"chave incompatível (não é Ed25519): {caminho}")
    return chave


def _carregar_publica(caminho):
    pem = _ler(caminho, TAMANHO_MAXIMO_PEM)
    try:
        chave = serialization.load_pem_public_key(pem)
    except (ValueError, UnsupportedAlgorithm):
        raise ErroSeguranca(
            f"o arquivo não é uma chave pública PEM válida: {caminho}"
        ) from None
    if not isinstance(chave, Ed25519PublicKey):
        raise ErroSeguranca(f"chave incompatível (não é Ed25519): {caminho}")
    return chave


def assinar(caminho_arquivo, caminho_privada, caminho_assinatura):
    """Assina os bytes originais (Ed25519 puro, sem pré-hash da aplicação)."""
    chave = _carregar_privada(caminho_privada)
    assinatura = chave.sign(_ler(caminho_arquivo))
    _criar_arquivo(caminho_assinatura, assinatura)


def verificar(caminho_arquivo, caminho_publica, caminho_assinatura):
    """Retorna True somente se a biblioteca confirmar a assinatura."""
    chave = _carregar_publica(caminho_publica)
    dados = _ler(caminho_arquivo)
    # Um byte a mais basta para detectar assinatura com tamanho excedente.
    assinatura = _ler(caminho_assinatura, TAMANHO_ASSINATURA + 1)
    if len(assinatura) != TAMANHO_ASSINATURA:
        return False
    try:
        chave.verify(assinatura, dados)
    except InvalidSignature:
        return False
    return True
