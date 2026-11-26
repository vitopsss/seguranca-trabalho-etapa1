#!/usr/bin/env python3
"""Interface de linha de comando da ferramenta `seguranca`.

Códigos de saída: 0 sucesso; 1 verificação falhou; 2 erro de uso ou execução.
"""

import argparse
import hmac
import sys

try:
    import cripto
except ImportError as erro:
    print(
        f"ERRO: dependência ausente ({erro}). "
        "Execute: python -m pip install -r requirements.txt",
        file=sys.stderr,
    )
    sys.exit(2)

SUCESSO, FALHA_VERIFICACAO, ERRO = 0, 1, 2


def cmd_keygen(args):
    cripto.gerar_chaves(args.chave_privada, args.chave_publica)
    print(f"Chave privada gravada em: {args.chave_privada}")
    print(f"Chave pública gravada em: {args.chave_publica}")
    print("Atenção: a chave privada não tem senha. Não compartilhe nem versione.")
    return SUCESSO


def cmd_hash(args):
    print(cripto.calcular_hash(args.arquivo))
    return SUCESSO


def cmd_check(args):
    referencia = cripto.normalizar_hash(args.hash_referencia)
    calculado = cripto.calcular_hash(args.arquivo)
    if hmac.compare_digest(calculado, referencia):
        print("HASH CORRESPONDE à referência.")
        return SUCESSO
    print("HASH DIVERGENTE: o arquivo não corresponde à referência.")
    print(f"Calculado : {calculado}")
    print(f"Referência: {referencia}")
    return FALHA_VERIFICACAO


def cmd_sign(args):
    cripto.assinar(args.arquivo, args.chave_privada, args.assinatura)
    print(f"Assinatura gravada em: {args.assinatura}")
    return SUCESSO


def cmd_verify(args):
    if cripto.verificar(args.arquivo, args.chave_publica, args.assinatura):
        print("ASSINATURA VÁLIDA")
        return SUCESSO
    print("ASSINATURA INVÁLIDA")
    return FALHA_VERIFICACAO


def criar_parser():
    parser = argparse.ArgumentParser(
        prog="seguranca",
        description="Integridade (SHA-256) e assinatura digital (Ed25519) de arquivos.",
        epilog="Saída: 0 sucesso; 1 verificação falhou; 2 erro de uso ou execução.",
    )
    comandos = parser.add_subparsers(dest="comando", required=True, metavar="comando")

    def novo(nome, funcao, ajuda, *argumentos):
        sub = comandos.add_parser(nome, help=ajuda, description=ajuda)
        for argumento in argumentos:
            sub.add_argument(argumento)
        sub.set_defaults(funcao=funcao)

    novo("keygen", cmd_keygen, "gera um par de chaves Ed25519",
         "chave_privada", "chave_publica")
    novo("hash", cmd_hash, "calcula o SHA-256 de um arquivo", "arquivo")
    novo("check", cmd_check, "compara o SHA-256 com uma referência",
         "arquivo", "hash_referencia")
    novo("sign", cmd_sign, "assina um arquivo",
         "arquivo", "chave_privada", "assinatura")
    novo("verify", cmd_verify, "verifica a assinatura de um arquivo",
         "arquivo", "chave_publica", "assinatura")
    return parser


def main(argv=None):
    # Evita que um console sem suporte a algum caractere derrube a execução.
    for fluxo in (sys.stdout, sys.stderr):
        fluxo.reconfigure(errors="replace")

    args = criar_parser().parse_args(argv)
    try:
        return args.funcao(args)
    except cripto.ErroSeguranca as erro:
        print(f"ERRO: {erro}", file=sys.stderr)
    except MemoryError:
        print("ERRO: memória insuficiente para processar o arquivo.", file=sys.stderr)
    except Exception as erro:  # nunca confundir falha inesperada com código 0 ou 1
        print(f"ERRO inesperado: {type(erro).__name__}: {erro}", file=sys.stderr)
    return ERRO


if __name__ == "__main__":
    sys.exit(main())
