from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from integrations import registry

# Public content -----------------------------------------------------------------

GUIDE_STEPS: List[dict] = [
    {
        "title": "1. Defina os metadados basicos",
        "body": (
            "Preencha `name`, `description`, `type` e `mode`. O tipo define o contexto "
            "(`incident` ou `artifact`) e o modo determina se o gatilho e automatico ou manual."
        ),
        "items": [
            "Use nomes objetivos (ex.: \"Phishing triage\").",
            "Habilite o playbook apenas quando estiver pronto para uso (`enabled`).",
            "Descreva o objetivo e os pre requisitos para que o time entenda rapidamente o fluxo.",
        ],
    },
    {
        "title": "2. Configure disparos ou filtros",
        "body": (
            "Playbooks automaticos exigem `triggers` com eventos como `incident.created` ou "
            "`artifact.created`. Playbooks manuais ignoram triggers e utilizam `filters` para "
            "controlar quando aparecem na interface."
        ),
        "items": [
            "Eventos suportados: incident.created, incident.updated, artifact.created.",
            "Filtros de trigger aceitam chaves como labels, status, severity, type ou changed_fields.",
            "Filtros manuais usam `target` (`incident` ou `artifact`) e `conditions` para labels, tipos e valores.",
        ],
    },
    {
        "title": "3. Modele os steps",
        "body": (
            "Cada item em `steps` deve ter `name`, `action` e `input`. Combine atualizacoes de incidente, "
            "criacao de tarefas, comunicacoes e integracoes externas."
        ),
        "items": [
            "Prefira nomes em snake_case para facilitar a leitura nos logs.",
            "Documente apenas os campos necessarios dentro de `input`.",
            "A execucao atual e linear, mas cada step pode usar `when` para condicionais simples.",
            "Garanta que todas as acoes externas possuam as credenciais e secrets configurados.",
        ],
    },
    {
        "title": "4. Defina comportamento em caso de erro",
        "body": (
            "Use `on_error: \"continue\"` para seguir com o fluxo mesmo que um passo falhe ou `stop` para interromper "
            "a execucao imediatamente."
        ),
        "items": [
            "Logue mensagens claras nos steps para facilitar troubleshooting.",
            "Considere adicionar notas ou labels no incidente quando ocorrer um erro critico.",
            "Placeholders simples em `input` sao resolvidos no runtime, por exemplo `{{incident.id}}`, `{{artifact.value}}` e `{{results.step_name.field}}`.",
            "Filtros simples em pipeline tambem sao suportados, como `{{incident.assignee.username|default:\"unassigned\"|upper}}`.",
            "Use `when` com operadores como `equals`, `in`, `contains`, `all`, `any` e `not` para controlar a execucao de um step.",
        ],
    },
    {
        "title": "5. Valide e publique",
        "body": (
            "Utilize a pagina de criacao/edicao ou o endpoint `/api/v1/playbooks/validate/` para validar a DSL. "
            "Execute em um incidente de laboratorio e revise a timeline e os logs de execucao."
        ),
        "items": [
            "Versione a DSL junto com o repositorio da equipe.",
            "Planeje testes periodicos para garantir que as integracoes externas continuam respondendo.",
        ],
    },
]

DSL_SCAFFOLD = """{
  "name": "Phishing triage",
  "description": "Fluxo de resposta padrao para phishing reportado.",
  "type": "incident",
  "mode": "automatic",
  "enabled": true,
  "triggers": [
    {
      "event": "incident.created",
      "filters": {"labels": ["phishing"]}
    }
  ],
  "steps": [
    {
      "name": "registrar_contexto",
      "action": "incident.add_note",
      "input": {"message": "Playbook iniciado automaticamente"}
    }
  ],
  "on_error": "continue"
}"""

REFERENCE_SNIPPETS: List[dict] = [
    {
        "title": "Playbook manual para incidentes",
        "snippet": """{
  "name": "Phishing checklist",
  "type": "incident",
  "mode": "manual",
  "filters": [
    {"target": "incident", "conditions": {"labels": ["phishing"], "severity": ["MEDIUM", "HIGH"]}}
  ],
  "steps": [
    {"name": "abrir_tarefa", "action": "task.create", "input": {"title": "Validar anexos", "owner": "analyst"}},
    {"name": "registrar_nota", "action": "incident.add_note", "input": {"message": "Checklist manual executado"}}
  ],
  "on_error": "continue"
}""",
    },
    {
        "title": "Playbook manual para artefatos",
        "snippet": """{
  "name": "IOC enrichment manual",
  "type": "artifact",
  "mode": "manual",
  "filters": [
    {"target": "artifact", "conditions": {"type": ["DOMAIN"]}}
  ],
  "steps": [
    {"name": "consultar_virustotal", "action": "virustotal.domain_report", "input": {}},
    {"name": "anotar_resultado", "action": "incident.add_note", "input": {"message": "Dominio enriquecido manualmente"}}
  ],
  "on_error": "continue"
}""",
    },
    {
        "title": "Envio de arquivo para VirusTotal",
        "snippet": """{
  "name": "File upload to VT",
  "type": "artifact",
  "mode": "manual",
  "filters": [
    {"target": "artifact", "conditions": {"type": ["FILE"]}}
  ],
  "steps": [
    {"name": "enviar_vt", "action": "virustotal.file_upload", "input": {}},
    {"name": "consultar_vt", "action": "virustotal.file_report", "input": {"artifact_type": "FILE"}},
    {"name": "registrar_nota", "action": "incident.add_note", "input": {"message": "Arquivo enviado ao VirusTotal; verifique o status nos atributos."}}
  ],
  "on_error": "continue"
}""",
    },
    {
        "title": "Disparo automatico com webhook",
        "snippet": """{
  "name": "Notify SOC via webhook",
  "type": "incident",
  "mode": "automatic",
  "triggers": [
    {"event": "incident.updated", "filters": {"changed_fields": ["severity"], "severity": ["HIGH", "CRITICAL"]}}
  ],
  "steps": [
    {
      "name": "notificar_soc",
      "action": "http_webhook.post",
      "input": {
        "url": "https://hooks.soc.local/incident",
        "payload": {
          "event": "incident.updated",
          "source": "basilio-soar-demo",
          "severity_gate": "HIGH_OR_CRITICAL"
        }
      }
    }
  ],
  "on_error": "continue"
}""",
    },
]

ACTION_METADATA: Dict[str, Dict[str, object]] = {
    "incident.add_note": {
        "category": "Incidente",
        "summary": "Registra nota ou evento na timeline do incidente.",
        "inputs": {
            "message": "Texto obrigatorio da nota.",
            "entry_type": "Opcional. Tipo da entrada (padrao NOTE).",
            "meta": "Campos extras armazenados junto a nota.",
        },
    },
    "incident.add_label": {
        "category": "Incidente",
        "summary": "Adiciona uma unica label ao incidente.",
        "inputs": {"label": "Nome da label obrigatoria."},
        "notes": "Tambem disponivel `incident.add_labels` para uma lista.",
    },
    "incident.add_labels": {
        "category": "Incidente",
        "summary": "Adiciona varias labels ao incidente.",
        "inputs": {"labels": "Lista de labels a adicionar."},
    },
    "incident.update_status": {
        "category": "Incidente",
        "summary": "Atualiza o status do incidente.",
        "inputs": {"status": "Novo status", "reason": "Motivo opcional gravado na timeline."},
    },
    "incident.assign": {
        "category": "Incidente",
        "summary": "Atribui o incidente para um usuario.",
        "inputs": {"assignee": "Username ou id do usuario.", "assignee_id": "Alias para `assignee`."},
    },
    "incident.update_impact": {
        "category": "Incidente",
        "summary": "Atualiza metadados de impacto e classificacao.",
        "inputs": {
            "impact_systems": "Lista de sistemas afetados.",
            "risk_score": "Pontuacao numerica de risco.",
            "severity": "Nova severidade sugerida.",
            "estimated_cost": "Custo estimado (decimal).",
            "business_unit": "Unidade de negocio envolvida.",
            "data_classification": "Classificacao de dados.",
        },
    },
    "incident.escalate": {
        "category": "Incidente",
        "summary": "Define nivel de escalacao e alvos de notificacao.",
        "inputs": {"level": "Nivel de escalacao (texto livre).", "targets": "Lista de destinatarios."},
    },
    "incident.log_action": {
        "category": "Incidente",
        "summary": "Cria entrada no audit log com verbo customizado.",
        "inputs": {"verb": "Identificador obrigatorio.", "meta": "Dicionario opcional com detalhes."},
    },
    "task.create": {
        "category": "Tarefas",
        "summary": "Cria follow up vinculado ao incidente.",
        "inputs": {
            "title": "Titulo da tarefa (obrigatorio).",
            "owner": "Username ou id do responsavel (opcional).",
            "eta": "Data limite ISO 8601.",
        },
    },
    "task.complete": {
        "category": "Tarefas",
        "summary": "Marca tarefa como concluida ou nao.",
        "inputs": {
            "task_id": "Identificador da tarefa (obrigatorio se `title` ausente).",
            "title": "Titulo para busca alternativa.",
            "done": "Booleano (padrao True).",
        },
    },
    "communication.log": {
        "category": "Comunicacao",
        "summary": "Registra uma comunicacao interna no incidente.",
        "inputs": {
            "channel": "Canal (padrao internal).",
            "recipient_team": "Equipe destino.",
            "recipient_user": "Username ou id do usuario destino.",
            "message": "Mensagem obrigatoria.",
        },
    },
    "artifact.create": {
        "category": "Artefatos",
        "summary": "Cria novo artefato associado ao incidente.",
        "inputs": {"value": "Valor do artefato (obrigatorio).", "type": "Tipo (padrao OTHER)."},
    },
    "artifact.extract_domain_from_email": {
        "category": "Artefatos",
        "summary": "Extrai dominio de um email e cria artefato DOMAIN.",
        "inputs": {
            "email": "Endereco para extracao (opcional se `artifact_id`).",
            "artifact_id": "ID de um artefato de email existente.",
        },
        "notes": "Adiciona label `domain-extracted` ao incidente.",
    },
    "virustotal.domain_report": {
        "category": "Enriquecimento",
        "summary": "Consulta dominio no VirusTotal.",
        "inputs": {
            "domain": "Dominio explicito (opcional).",
            "artifact_type": "Tipo de artefato usado se dominio nao for informado (padrao DOMAIN).",
        },
        "notes": "Exige `VIRUSTOTAL_API_KEY` e consulta a API real. Cria nota na timeline e preenche `artifact.attributes['virustotal']` com reputacao, estatisticas resumidas e dados basicos de WHOIS.",
    },
    "virustotal.ip_report": {
        "category": "Enriquecimento",
        "summary": "Consulta reputacao de IP no VirusTotal.",
        "inputs": {
            "ip": "IP explicito (opcional).",
            "artifact_type": "Tipo de artefato usado caso o IP nao seja informado (padrao IP).",
        },
        "notes": "Exige `VIRUSTOTAL_API_KEY` e consulta a API real. Cria nota na timeline e atualiza `artifact.attributes['virustotal']` com reputacao, localizacao e estatisticas resumidas.",
    },
    "virustotal.url_report": {
        "category": "Enriquecimento",
        "summary": "Consulta reputacao de URL no VirusTotal.",
        "inputs": {
            "url": "URL explicita (opcional).",
            "artifact_type": "Tipo de artefato usado caso a URL nao seja informada (padrao URL).",
        },
        "notes": "Exige `VIRUSTOTAL_API_KEY` e consulta a API real. Atualiza `artifact.attributes['virustotal']` com reputacao, estatisticas e ultima resposta HTTP observada.",
    },
    "virustotal.file_report": {
        "category": "Enriquecimento",
        "summary": "Consulta hash de arquivo no VirusTotal.",
        "inputs": {
            "hash": "Hash explicito (SHA256/SHA1/MD5).",
            "artifact_type": "Tipo de artefato usado caso o hash nao seja informado (padrao HASH).",
        },
        "notes": "Exige `VIRUSTOTAL_API_KEY` e consulta a API real. Salva reputacao e metadados basicos (nome, tipo, estatisticas) do arquivo consultado.",
    },
    "http_webhook.post": {
        "category": "Integracoes",
        "summary": "Envia webhook HTTP real.",
        "inputs": {
            "url": "Destino obrigatorio.",
            "method": "Metodo HTTP opcional (padrao POST).",
            "payload": "JSON opcional enviado no corpo.",
            "body": "Corpo bruto opcional, usado quando payload nao for informado.",
            "headers": "Cabecalhos adicionais.",
            "timeout": "Timeout em segundos (padrao 15).",
        },
        "notes": "Executa requisicao HTTP real via `requests`, falha em erro de rede/HTTP e retorna status, headers e corpo da resposta. Placeholders e filtros simples no `input` sao resolvidos antes da action ser executada.",
    },
}


# Helpers consumed by the UI ------------------------------------------------------


def get_action_catalog() -> List[dict]:
    """Return actions grouped by category with metadata."""
    grouped: Dict[str, List[dict]] = defaultdict(list)
    for action_name in registry.list_actions():
        metadata = ACTION_METADATA.get(
            action_name,
            {
                "category": "Outros",
                "summary": "Descricao em desenvolvimento.",
                "inputs": {},
                "notes": "",
            },
        )
        grouped[metadata["category"]].append(
            {
                "name": action_name,
                "summary": metadata.get("summary", ""),
                "inputs": metadata.get("inputs", {}),
                "notes": metadata.get("notes", ""),
            }
        )
    catalog = []
    for category in sorted(grouped):
        catalog.append(
            {
                "category": category,
                "actions": sorted(grouped[category], key=lambda item: item["name"]),
            }
        )
    return catalog


def get_guide_steps() -> List[dict]:
    return GUIDE_STEPS


def get_reference_snippets() -> List[dict]:
    return REFERENCE_SNIPPETS
