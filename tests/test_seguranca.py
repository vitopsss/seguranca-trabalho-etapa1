"""Testes automatizados, executando a CLI como um terceiro faria.

Usam somente arquivos fictícios, criados em diretórios temporários.
"""

import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

RAIZ = Path(__file__).resolve().parent.parent
CLI = RAIZ / "src" / "seguranca.py"
# Vetor de teste oficial do SHA-256 para a mensagem "abc" (FIPS 180-2).
SHA256_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
CONTEUDO = b"Declaracao ficticia\r\nlinha 2\n\x00\xff"


class Base(unittest.TestCase):
    def setUp(self):
        temporario = tempfile.TemporaryDirectory()
        self.addCleanup(temporario.cleanup)
        self.dir = Path(temporario.name)
        (self.dir / "documento.txt").write_bytes(CONTEUDO)

    def rodar(self, *args):
        return subprocess.run(
            [sys.executable, str(CLI), *args],
            cwd=self.dir,
            capture_output=True,
            encoding="utf-8",
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        )

    def esperar(self, codigo, *args):
        resultado = self.rodar(*args)
        self.assertEqual(
            resultado.returncode, codigo, resultado.stdout + resultado.stderr
        )
        self.assertNotIn("Traceback", resultado.stderr)
        return resultado

    def chaves(self, prefixo="a"):
        self.esperar(0, "keygen", f"{prefixo}.key.pem", f"{prefixo}.pub.pem")

    def assinar(self):
        self.chaves()
        self.esperar(0, "sign", "documento.txt", "a.key.pem", "doc.sig")

    def verificar(self, codigo, chave="a.pub.pem", assinatura="doc.sig"):
        resultado = self.esperar(codigo, "verify", "documento.txt", chave, assinatura)
        if codigo == 0:
            self.assertEqual(resultado.stdout.strip(), "ASSINATURA VÁLIDA")
        else:
            self.assertNotIn("ASSINATURA VÁLIDA", resultado.stdout)
        return resultado


class TestesObrigatorios(Base):
    def test_ti01_calcula_sha256(self):
        (self.dir / "abc.txt").write_bytes(b"abc")
        self.assertEqual(self.esperar(0, "hash", "abc.txt").stdout.strip(), SHA256_ABC)

    def test_ti02_detecta_modificacao_pelo_hash(self):
        original = self.esperar(0, "hash", "documento.txt").stdout.strip()
        self.esperar(0, "check", "documento.txt", original)
        (self.dir / "documento.txt").write_bytes(CONTEUDO + b"!")
        resultado = self.esperar(1, "check", "documento.txt", original)
        self.assertIn("DIVERGENTE", resultado.stdout)

    def test_ti03_gera_par_de_chaves_pem(self):
        self.chaves()
        pem_privada = (self.dir / "a.key.pem").read_bytes()
        pem_publica = (self.dir / "a.pub.pem").read_bytes()
        self.assertTrue(pem_privada.startswith(b"-----BEGIN PRIVATE KEY-----"))
        self.assertTrue(pem_publica.startswith(b"-----BEGIN PUBLIC KEY-----"))
        privada = serialization.load_pem_private_key(pem_privada, None)
        publica = serialization.load_pem_public_key(pem_publica)
        self.assertIsInstance(privada, ed25519.Ed25519PrivateKey)
        self.assertIsInstance(publica, ed25519.Ed25519PublicKey)

    def test_ti04_assina_e_verifica_original(self):
        self.assinar()
        self.assertEqual(len((self.dir / "doc.sig").read_bytes()), 64)
        self.verificar(0)

    def test_ti05_arquivo_alterado_invalida_assinatura(self):
        self.assinar()
        # Trocar apenas o fim de linha já deve invalidar.
        (self.dir / "documento.txt").write_bytes(CONTEUDO.replace(b"\r\n", b"\n"))
        self.assertIn("INVÁLIDA", self.verificar(1).stdout)

    def test_ti06_outra_chave_publica(self):
        self.assinar()
        self.chaves("b")
        self.assertIn("INVÁLIDA", self.verificar(1, chave="b.pub.pem").stdout)


class TestesDeInteroperabilidade(Base):
    def test_assinatura_direta_sobre_os_bytes_originais(self):
        """Confere a saída da CLI sem usar o código da ferramenta."""
        self.assinar()
        publica = serialization.load_pem_public_key(
            (self.dir / "a.pub.pem").read_bytes()
        )
        publica.verify((self.dir / "doc.sig").read_bytes(), CONTEUDO)  # levanta se falhar

    def test_aceita_assinatura_e_chave_geradas_externamente(self):
        privada = ed25519.Ed25519PrivateKey.generate()
        (self.dir / "ext.pub.pem").write_bytes(
            privada.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        (self.dir / "doc.sig").write_bytes(privada.sign(CONTEUDO))
        self.verificar(0, chave="ext.pub.pem")

    def test_arquivo_vazio_e_arquivo_maior_que_um_bloco(self):
        casos = (("vazio.bin", b""), ("grande.bin", os.urandom(3_000_000)))
        for nome, dados in casos:
            with self.subTest(nome):
                (self.dir / nome).write_bytes(dados)
                saida = self.esperar(0, "hash", nome).stdout.strip()
                self.assertEqual(saida, hashlib.sha256(dados).hexdigest())

    def test_check_aceita_referencia_em_maiusculas(self):
        referencia = hashlib.sha256(CONTEUDO).hexdigest().upper()
        self.esperar(0, "check", "documento.txt", referencia)

    def test_exemplo_versionado_continua_valido(self):
        exemplos = RAIZ / "exemplos"
        self.esperar(
            0,
            "verify",
            str(exemplos / "documento.txt"),
            str(exemplos / "chave_publica.pem"),
            str(exemplos / "documento.txt.sig"),
        )


class TestesDeErros(Base):
    def erro(self, trecho, *args):
        self.assertIn(trecho, self.esperar(2, *args).stderr)

    def test_arquivo_inexistente(self):
        self.erro("não encontrado", "hash", "nao_existe.txt")

    def test_diretorio_no_lugar_de_arquivo(self):
        self.erro("diretório", "hash", ".")

    def test_hash_de_referencia_malformado(self):
        for referencia in ("", "abc", "z" * 64, "a" * 63, "a" * 65):
            with self.subTest(referencia=referencia):
                self.erro("referência inválido", "check", "documento.txt", referencia)

    def test_assinatura_com_tamanho_errado(self):
        self.assinar()
        valida = (self.dir / "doc.sig").read_bytes()
        for dados in (b"", valida[:63], valida + b"\n"):
            with self.subTest(tamanho=len(dados)):
                (self.dir / "ruim.sig").write_bytes(dados)
                self.verificar(1, assinatura="ruim.sig")

    def test_assinatura_com_um_bit_alterado(self):
        self.assinar()
        dados = bytearray((self.dir / "doc.sig").read_bytes())
        dados[0] ^= 1
        (self.dir / "ruim.sig").write_bytes(bytes(dados))
        self.verificar(1, assinatura="ruim.sig")

    def test_assinatura_inexistente(self):
        self.chaves()
        self.verificar(2, assinatura="nao_existe.sig")

    def test_chaves_trocadas_ou_corrompidas(self):
        self.assinar()
        (self.dir / "lixo.pem").write_bytes(b"isto nao e uma chave")
        for chave in ("a.key.pem", "lixo.pem"):
            with self.subTest(chave=chave):
                self.verificar(2, chave=chave)
        self.erro("chave privada", "sign", "documento.txt", "a.pub.pem", "x.sig")
        self.assertFalse((self.dir / "x.sig").exists())

    def test_chave_de_outro_algoritmo(self):
        self.assinar()
        outra = ec.generate_private_key(ec.SECP256R1())
        (self.dir / "ec.key.pem").write_bytes(
            outra.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        (self.dir / "ec.pub.pem").write_bytes(
            outra.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        self.erro("incompatível", "sign", "documento.txt", "ec.key.pem", "x.sig")
        self.assertIn("incompatível", self.verificar(2, chave="ec.pub.pem").stderr)

    def test_chave_privada_com_senha(self):
        (self.dir / "senha.pem").write_bytes(
            ed25519.Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(b"senha-de-teste"),
            )
        )
        self.erro("senha", "sign", "documento.txt", "senha.pem", "x.sig")

    def test_nao_sobrescreve_arquivos(self):
        self.assinar()
        for destino in ("documento.txt", "a.key.pem", "doc.sig"):
            with self.subTest(destino=destino):
                antes = (self.dir / destino).read_bytes()
                self.erro("já existe", "sign", "documento.txt", "a.key.pem", destino)
                self.assertEqual((self.dir / destino).read_bytes(), antes)
        self.erro("já existe", "keygen", "a.key.pem", "novo.pub.pem")

    def test_keygen_nao_deixa_par_incompleto(self):
        for publica in ("nao/existe/pub.pem", "nova.key.pem"):
            with self.subTest(publica=publica):
                self.esperar(2, "keygen", "nova.key.pem", publica)
                self.assertFalse((self.dir / "nova.key.pem").exists())

    def test_uso_incorreto(self):
        self.esperar(2)
        self.esperar(2, "verify", "documento.txt")
        self.esperar(2, "inexistente")


if __name__ == "__main__":
    unittest.main()
