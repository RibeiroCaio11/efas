# Agente Autônomo de Segurança Cibernética

Um sistema de monitoramento e proteção de segurança cibernética 100% autônomo que detecta, analisa e responde a ameaças em tempo real utilizando Inteligência Artificial (LLM), LangGraph para fluxos de decisão, Model Context Protocol (MCP), bloqueio de firewall real e redirecionamento para honeypot.

## Características Principais

- 🤖 **100% Autônomo**: Funciona continuamente sem intervenção humana
- 🧠 **LLM Integrado**: Utiliza modelos de linguagem para análise avançada de ameaças
- 🔍 **Explicabilidade Total**: Rastreamento detalhado de cada decisão do sistema com visualização gráfica
- 🔄 **Auto-otimização**: Aprende e melhora com base em feedback e experiência passada
- 📊 **LangGraph**: Arquitetura baseada em grafo para fluxos de decisão complexos
- 💡 **MCP (Model Context Protocol)**: Gerenciamento avançado de contexto para correlação automática de eventos
- 🔒 **Bloqueio Real de IPs**: Implementa regras diretas no firewall do sistema
- 🍯 **Honeypot**: Redireciona atacantes para ambiente controlado
- ⚡ **Tomada de Decisão Inteligente**: Resposta adaptativa baseada no nível de risco
- 📈 **Visualização em Tempo Real**: Interface intuitiva para monitoramento contínuo
- 🔔 **Notificações Multi-canal**: Alertas via Telegram e Discord

## Arquitetura

O sistema foi implementado usando arquitetura modular orientada a objetos com fluxos baseados em grafos, dividido nos seguintes componentes:

- **Config**: Gerencia todas as configurações e chaves de API
- **SecurityLogger**: Sistema de logs com rotação de arquivos
- **ThreatIntelligence**: Análise de ameaças usando LangGraph, LLM e múltiplas fontes (VirusTotal, AbuseIPDB)
- **NetworkMonitor**: Monitoramento contínuo de rede em thread separada
- **SecurityAgent**: Agente de segurança com processamento paralelo e tomada de decisão autônoma
- **NotificationSystem**: Sistema de notificações para alertas via Telegram e Discord
- **SecurityUI**: Interface do usuário construída com Streamlit, com atualização automática

## Fluxo de Análise de Ameaças

O sistema utiliza LangGraph para implementar um fluxo de análise de ameaças sofisticado:

1. **check_rules**: Verificação de regras predefinidas para rápida classificação
2. **fetch_threat_intel**: Coleta de dados de inteligência de ameaças externas
3. **analyze_with_llm**: Análise semântica avançada usando LLM
4. **calculate_risk_score**: Cálculo de pontuação de risco baseado em evidências
5. **adjust_with_feedback**: Ajuste da análise com base em feedback histórico
6. **finalize_analysis**: Determinação final do nível de risco

## Requisitos

- Python 3.8+
- Streamlit
- langchain
- langchain-openai
- langgraph
- Plotly
- Pandas
- Requests
- python-dotenv
- python-dateutil

## Instalação

```bash
pip install -r requirements.txt
```

## Configuração

Para utilizar todas as funcionalidades:

1. Configure sua chave de API OpenAI em `config.py` para habilitar o LLM
2. Execute o aplicativo com permissões de administrador para permitir modificações no firewall
3. Opcional: Configure um honeypot real em sua rede para redirecionamento efetivo
4. Para notificações, configure:
   - Token do bot e Chat ID do Telegram
   - URL do webhook do Discord

## Uso

Execute o aplicativo Streamlit:

```bash
streamlit run main.py
```

## Níveis de Resposta Automática

O sistema responde automaticamente de acordo com o nível de ameaça:

- **Alto Risco**: Bloqueio automático no firewall OU redirecionamento para honeypot
- **Médio Risco**: Adição ao monitoramento contínuo e alerta
- **Baixo Risco**: Registro nos logs para análise posterior

## Como Funciona o Agente Autônomo

1. Ciclo de monitoramento automático a cada 10 segundos
2. Simulação automática de ataques a cada 7 segundos (pode ser desativada pela interface)
3. Análise da ameaça com fluxo baseado em grafo via LangGraph
4. Explicabilidade detalhada de cada decisão tomada pelo sistema
5. Auto-otimização através de feedback e aprendizado contínuo
6. Correlação automática de eventos a cada 15 segundos via MCP
7. Resposta automática de acordo com o nível de risco
8. Atualização da interface a cada 5 segundos
9. Bloqueio real de IPs mal-intencionados no firewall do sistema
10. Notificações em tempo real para Telegram e Discord

## Explicabilidade e Auto-otimização

O sistema implementa recursos avançados para garantir confiabilidade e melhoria contínua:

- **Rastreamento de Decisões**: Cada etapa do processo de análise é documentada com motivos e nível de confiança
- **Visualização do Processo Decisório**: Gráficos mostram a evolução da confiança durante a análise
- **Feedback Loop**: Os usuários podem fornecer feedback sobre análises para melhorar decisões futuras
- **Aprendizagem Contínua**: O sistema ajusta automaticamente suas análises com base em experiências anteriores
- **Ajuste de Confiança**: A confiança do sistema aumenta à medida que recebe confirmações de decisões corretas

## Model Context Protocol (MCP)

O MCP é um protocolo de gestão de contexto que permite ao sistema:

- Manter consciência situacional contínua
- Correlacionar automaticamente eventos de segurança aparentemente não relacionados
- Identificar padrões complexos de ataque
- Adaptar o nível de confiança com base em novas evidências
- Fornecer contexto enriquecido para o processo de tomada de decisão
- Incorporar feedback para melhorar análises futuras

## Diferenciais Tecnológicos

- **Arquitetura baseada em Grafo**: Utiliza LangGraph para fluxos de decisão avançados e adaptáveis
- **Explicabilidade Total**: Cada decisão do sistema é documentada e visualizável
- **Auto-otimização**: Aprende continuamente e melhora com o tempo através de feedback
- **Autonomia Verdadeira**: Não requer intervenção humana para operação contínua
- **LLM Integrado**: Análise avançada de ameaças por modelo de linguagem
- **MCP Avançado**: Correlação automática de eventos e padrões
- **Controle de Simulação**: Capacidade de ativar/desativar simulações de ataque
- **Ações Reais de Proteção**: Executa comandos diretos no firewall do sistema operacional
- **Arquitetura Paralela**: Threads separadas para monitoramento e análise
- **Notificações Multi-canal**: Alertas em tempo real para plataformas externas

## Estrutura do Projeto

```
.
├── main.py                  # Arquivo principal
├── config.py                # Configurações e variáveis de ambiente 
├── logger.py                # Sistema de logs
├── threat_intelligence.py   # Análise de ameaças com LangGraph e LLM
├── network_monitor.py       # Monitoramento contínuo de rede
├── security_agent.py        # Agente de segurança autônomo
├── notification.py          # Sistema de notificações (Telegram/Discord)
├── front.py                 # Interface Streamlit com visualizações e feedback
├── requirements.txt         # Dependências do projeto
└── logs/                    # Diretório de logs (criado automaticamente)
```
