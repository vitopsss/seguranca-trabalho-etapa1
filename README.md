# seguranca

Ferramenta de linha de comando para conferir a integridade de arquivos com SHA-256 e assiná-los com Ed25519. Trabalho Prático, Etapa 1, da disciplina de Segurança da Informação (IFAM).

O relatório técnico está em [docs/RELATORIO_TECNICO.md](docs/RELATORIO_TECNICO.md).

## Instalação

É preciso ter Python 3 instalado. Testamos com Python 3.13.7 no Windows 11. A única dependência externa é a biblioteca [`cryptography`](https://cryptography.io/).

Todos os comandos deste README são executados na raiz do repositório.

Windows (PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Se o PowerShell bloquear a ativação, pule essa linha e use `.\.venv\Scripts\python.exe` no lugar de `python`.

Linux ou macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Execução

O comando `seguranca` do enunciado é executado como `python src/seguranca.py`. A ordem dos argumentos é a mesma.

| Comando | O que faz |
|---|---|
| `python src/seguranca.py keygen chave_privada.pem chave_publica.pem` | Gera um par de chaves Ed25519 |
| `python src/seguranca.py hash documento.txt` | Mostra o SHA-256 do arquivo |
| `python src/seguranca.py check documento.txt HASH_REFERENCIA` | Compara o SHA-256 do arquivo com a referência |
| `python src/seguranca.py sign documento.txt chave_privada.pem assinatura.sig` | Assina o arquivo |
| `python src/seguranca.py verify documento.txt chave_publica.pem assinatura.sig` | Verifica a assinatura |

`python src/seguranca.py --help` mostra a ajuda.

### Códigos de saída

| Código | Significado |
|---|---|
| 0 | Sucesso (em `check`, o hash corresponde; em `verify`, a assinatura é válida) |
| 1 | A verificação falhou: hash divergente ou assinatura inválida |
| 2 | Erro de uso ou de execução (arquivo ausente, chave incompatível, destino existente etc.) |

Uma assinatura com tamanho diferente de 64 bytes conta como inválida (código 1). As mensagens de erro vão para a saída de erro e começam com `ERRO:`.

## Exemplos de uso

### Verificar o exemplo incluído

A pasta `exemplos/` tem um documento fictício, uma chave pública e a assinatura do documento. A chave privada correspondente foi gerada fora do projeto e apagada.

```bash
python src/seguranca.py verify exemplos/documento.txt exemplos/chave_publica.pem exemplos/documento.txt.sig
```

```
ASSINATURA VÁLIDA
```

```bash
python src/seguranca.py hash exemplos/documento.txt
```

```
391ee62ff3bb353a88b0c3aefa0d9cb9d58c7b5068ff05f8373fff14bd62b73d
```

```bash
python src/seguranca.py check exemplos/documento.txt 391ee62ff3bb353a88b0c3aefa0d9cb9d58c7b5068ff05f8373fff14bd62b73d
```

```
HASH CORRESPONDE à referência.
```

### Fluxo completo

```bash
python src/seguranca.py keygen chave_privada.pem chave_publica.pem
python src/seguranca.py sign exemplos/documento.txt chave_privada.pem assinatura.sig
python src/seguranca.py verify exemplos/documento.txt chave_publica.pem assinatura.sig
```

Para ver uma assinatura ser rejeitada, copie o documento, altere a cópia e rode `verify` sobre ela com a mesma assinatura. A saída é `ASSINATURA INVÁLIDA`, com código 1.

A ferramenta não sobrescreve arquivos. Para repetir o fluxo, apague as chaves e a assinatura anteriores ou use outros nomes. O `.gitignore` impede que arquivos `.pem` e `.sig` novos entrem no Git por engano.

A chave privada é gravada sem senha. Não a compartilhe nem a publique.

## Formatos

| Item | Formato |
|---|---|
| Hash | 64 caracteres hexadecimais minúsculos (`check` também aceita maiúsculas na referência) |
| Chave privada | PEM, PKCS#8, sem senha |
| Chave pública | PEM, SubjectPublicKeyInfo |
| Assinatura | Arquivo binário de 64 bytes, Ed25519 aplicado aos bytes originais do arquivo |

Os arquivos são lidos em modo binário, sem conversão de codificação ou de fim de linha.

## Testes

```bash
python -m unittest discover -s tests -v
```

São 23 testes, que executam a CLI como um usuário faria e usam arquivos fictícios em diretórios temporários. Os seis obrigatórios são `test_ti01` a `test_ti06`. Os outros cobrem interoperabilidade e tratamento de erros.

Registros de execução:

- [Testes automatizados](docs/evidencias/testes_automatizados.txt)
- [Interoperabilidade com OpenSSL](docs/evidencias/interoperabilidade_openssl.txt)

## Organização

```
src/seguranca.py        interface de linha de comando, mensagens e códigos de saída
src/cripto.py           SHA-256, chaves, assinatura, verificação e acesso a arquivos
tests/                  testes automatizados
exemplos/               documento fictício, chave pública e assinatura
docs/                   relatório técnico e evidências
requirements.txt        dependência
```
