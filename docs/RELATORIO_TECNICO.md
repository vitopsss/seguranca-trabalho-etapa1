# Relatório Técnico: Trabalho Prático, Etapa 1

## 1. Identificação

- **Integrantes:** João Victor Passos Lima, Luiz André, Antônio Lúcio
- **Turma:** V, Engenharia de Software (IFAM)
- **Linguagem:** Python
- **Repositório:** <https://github.com/vitopsss/seguranca-trabalho-etapa1>

## 2. Descrição da solução

As operações com Ed25519 e os formatos PEM usam `cryptography`. O SHA-256 usa `hashlib`, e a interface usa `argparse`, ambos da biblioteca padrão. Os testes usam `unittest`. Não implementamos algoritmos criptográficos por conta própria.

No código, `src/cripto.py` concentra as operações criptográficas e o acesso a arquivos. `src/seguranca.py` interpreta os comandos, exibe as mensagens e define o código de saída.

Principais decisões técnicas:

- O Ed25519 recebe os bytes originais do arquivo, sem pré-hash da aplicação. A leitura é binária, então uma troca de fim de linha já altera o resultado.
- O código 1 indica verificação que falhou e o 2, erro de uso ou execução, inclusive exceções inesperadas.
- A ferramenta não sobrescreve arquivos, para que um argumento trocado não apague uma chave ou um documento. Se a chave pública não puder ser criada, a privada é removida.
- O hash é calculado em blocos de 1 MiB. Assinatura e verificação carregam o arquivo inteiro, pois o Ed25519 puro, nessa interface, recebe a mensagem completa.
- Chaves de outro algoritmo, protegidas por senha ou corrompidas são recusadas com uma mensagem específica.

## 3. Funcionalidades implementadas

| Requisito | Funcionalidade | Comando |
|---|---|---|
| R01 | Geração do par Ed25519 (PKCS#8 e SubjectPublicKeyInfo) | `keygen` |
| R02 | SHA-256 de qualquer arquivo | `hash` |
| R03 | Comparação com um hash de referência | `check` |
| R04 | Assinatura em arquivo binário de 64 bytes | `sign` |
| R05 | Verificação com a chave pública | `verify` |
| R06 | Rejeição de assinatura inválida, inclusive após alteração do arquivo | `verify` |

Erros de arquivo, caminho, chave e entrada geram mensagens próprias. Instalação e exemplos estão no [README](../README.md).

## 4. Testes realizados

Os 23 testes automatizados passaram em Python 3.13.7 com `cryptography` 50.0.2, no Windows 11 ([saída completa](evidencias/testes_automatizados.txt); código em [`tests/test_seguranca.py`](../tests/test_seguranca.py)).

| Teste | Verificação | Resultado |
|---|---|---|
| TI01 | SHA-256 de "abc" igual ao vetor oficial | Aprovado |
| TI02 | Arquivo modificado gera divergência em `check` | Aprovado |
| TI03 | `keygen` produz chaves PEM Ed25519 válidas | Aprovado |
| TI04 | Assinatura do arquivo original é aceita e tem 64 bytes | Aprovado |
| TI05 | Alteração após a assinatura (só o fim de linha) é rejeitada | Aprovado |
| TI06 | Verificação com outra chave pública é rejeitada | Aprovado |
| Interoperabilidade | Verificação direta pela biblioteca, chave externa, arquivo vazio e de 3 MB | Aprovado |
| Erros | Entradas ausentes ou inválidas, assinatura adulterada, proteção contra sobrescrita | Aprovado |

Fizemos ainda um [teste com o OpenSSL](evidencias/interoperabilidade_openssl.txt). Ele aceitou a assinatura da ferramenta, e a ferramenta aceitou a chave e a assinatura geradas por ele. Com a mesma chave, as duas assinaturas saíram idênticas byte a byte. O SHA-256 também coincidiu com o do `sha256sum`.

## 5. Análise técnica e conclusão

Nos testes realizados, os requisitos R01 a R06 funcionaram conforme o contrato de interoperabilidade.

Quanto às limitações, a chave privada é gravada sem senha. A permissão restrita (0600) pedida na criação tem pouco efeito no Windows. O tamanho dos arquivos que podem ser assinados ou verificados depende da memória disponível. A ferramenta não liga uma chave a uma pessoa, não usa certificados, não trata revogação nem expiração e não registra a data da assinatura. Ela também não cifra o conteúdo dos documentos.

**Por que um hash SHA-256 isolado não comprova a autoria?** Porque o cálculo não usa segredo. Qualquer pessoa pode alterar o documento e calcular um novo hash. A comparação mostra apenas se o arquivo corresponde à referência, e só ajuda quando a referência vem de um canal confiável.

**Qual é o papel das chaves pública e privada?** A chave privada, mantida em segredo pelo titular, produz a assinatura. A chave pública, que pode ser distribuída, verifica se a assinatura corresponde ao arquivo e àquele par de chaves. Para atribuir a assinatura a uma pessoa, é preciso confirmar por um meio confiável que a chave pública é dela.

**Por que alterar um documento assinado invalida a assinatura?** A assinatura é calculada a partir da chave privada e dos bytes do documento (o Ed25519 usa SHA-512 internamente). A verificação refaz a conta com os bytes recebidos. Se eles mudaram, a equação de verificação deixa de ser satisfeita, e produzir uma nova assinatura válida exige a chave privada.

**Que cuidados faltam para produção?** Proteger a chave privada com senha forte ou guardá-la em um cofre de chaves ou HSM, com controle de acesso. Vincular chaves a identidades por certificados de uma infraestrutura de chaves públicas. Definir rotação, revogação, cópia de segurança e resposta a vazamentos. Usar carimbo do tempo confiável e registros de auditoria. Estabelecer limites de tamanho, manter as dependências atualizadas e submeter a solução a uma revisão de segurança independente.
