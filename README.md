# Sentinel SOC

Aplicação educacional de triagem de autenticações e investigação de alertas, desenvolvida com Streamlit, pandas e Plotly. **Todos os registros incluídos no repositório são sintéticos**. A ferramenta não confirma invasões nem substitui um SIEM.

## Funcionalidades

- Fila de alertas com seleção de linha para abrir investigação.
- Linha do tempo de eventos correlacionados por IP e usuário, notas temporárias do analista e relatório de caso em Markdown.
- Importação de CSV Sentinel, logs SSH (syslog tradicional e ISO 8601) e logs HTTP no formato combinado compatível com o parser.
- Anonimização opcional de IPs com pseudônimos SHA-256 truncados. Não constitui anonimização irreversível nem garante proteção de dados pessoais.
- Exploração de eventos, indicadores e exportação CSV.
- Limiares de detecção, fuso e faixa horária configuráveis na barra lateral.

## Regras de detecção

| Regra | Lógica | Severidade | MITRE ATT&CK | Limitação |
| --- | --- | --- | --- | --- |
| Falhas repetidas de autenticação | N falhas por IP e usuário na janela | Alta | T1110 | Pode incluir erros legítimos de senha |
| Sucesso após falhas repetidas | Sucesso após N falhas anteriores por IP e usuário | Crítica | T1110, T1078 | Não comprova comprometimento |
| Possível password spraying | Falhas do mesmo IP para N usuários distintos na janela | Alta | T1110.003 | NAT e proxies podem reunir vários usuários legítimos |
| Login em horário incomum | Sucesso em faixa horária configurada no fuso escolhido | Média | Sem técnica atribuída | Plantões e viagens podem produzir falsos positivos |

As regras avaliam eventos de autenticação. A primeira ocorrência que satisfaz cada regra por IP/usuário (ou IP para spraying) gera um alerta. A regra de sucesso exige falhas com timestamp estritamente anterior; a de falhas repetidas inclui eventos no instante do limiar.

## Execução

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
streamlit run app.py
```

## Testes e qualidade

```bash
pip install -r requirements-dev.txt
ruff check sentinel tests
pytest -q
```

O workflow testa pandas 2.x e 3.x com Python 3.11 e 3.12. **A compatibilidade com pandas 3 ainda depende de confirmação da execução do CI**; por isso o limite `pandas<3` permanece no arquivo de dependências.

Os testes incluem a amostra `data/sample_auth.csv`, cenários de spraying, horário incomum, importação SSH/HTTP e conjunto sintético de 200 mil eventos. O teste de 200 mil linhas verifica a saída, não é uma medição formal de desempenho.

## Formato dos eventos

CSV com colunas obrigatórias:

```text
timestamp,source_ip,username,event_type,status
2026-01-15T12:01:00Z,192.0.2.10,alice,authentication,failure
```

Para importar `auth.log` ou log HTTP, selecione **SSH / HTTP** na barra lateral. O parser reconhece linhas SSH com `Failed` ou `Accepted` e respostas HTTP 401, 403 ou 2xx no formato comum com data e usuário. Nem todo log HTTP representa uma autenticação; respostas 2xx podem produzir falsos positivos e exigem interpretação humana.

## Capturas da interface

As capturas reais da fila de alertas, investigação e indicadores serão adicionadas após validação visual em navegador. Não foram inseridas imagens simuladas.

## Limitações

- Sem ingestão contínua, retenção persistente, integração SIEM ou contenção automática.
- As notas de investigação existem somente durante a sessão Streamlit.
- A correlação por IP/usuário pode falhar em redes com NAT, proxies ou ataques distribuídos.
- O parser de logs é intencionalmente restrito a formatos conhecidos; linhas não reconhecidas não entram na análise.
- O ano do syslog tradicional é inferido do ano corrente pelo parser; prefira timestamps ISO 8601 com fuso.
- Não importe dados sensíveis em instâncias públicas.

Projeto de portfólio: [thlozz](https://github.com/thlozz). Licença MIT.
