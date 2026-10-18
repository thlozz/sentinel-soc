# Sentinel SOC

**Security Operations Dashboard** — detecção de eventos de autenticação em Python, com interface Streamlit e visualização Plotly. Projeto educacional de Blue Team, automação e engenharia de detecção.

## Funcionalidades (v0.1)
- Importação de logs CSV ou dados sintéticos de demonstração.
- Normalização e validação de timestamps em UTC.
- Regra de força bruta: N falhas por IP e usuário em uma janela configurável.
- Regra de autenticação bem-sucedida após repetidas falhas.
- Alertas com severidade, evidência e referência MITRE ATT&CK T1110.
- Dashboard de eventos, filtros e exportação CSV.

## Execução
```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

## Testes
```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

## Formato de entrada
CSV com as colunas obrigatórias:
`timestamp,source_ip,username,event_type,status`

- `timestamp`: data ISO 8601 (preferencialmente com fuso explícito).
- `event_type`: `authentication` para eventos avaliados pelas regras.
- `status`: `failure` ou `success`.
- IPs, usuários e dados do exemplo são **sintéticos**.

## Estrutura
```text
app.py                  Dashboard
sentinel/detector.py    Normalização e regras de detecção
data/sample_auth.csv    Dados sintéticos
tests/test_detector.py  Testes unitários
```

## Limitações
As regras são heurísticas e demonstrativas, não substituem um SIEM ou análise humana. A correlação considera IP + usuário; não cobre ataques distribuídos nem detecção comportamental avançada. Não importe dados sensíveis para instâncias públicas.

## Roadmap
- Mais regras (password spraying, login em horário incomum)
- Parser de logs SSH reais com anonimização
- Investigação de alertas e relatórios
- Detecção de anomalias com machine learning

Desenvolvido para portfólio por [thlozz](https://github.com/thlozz).