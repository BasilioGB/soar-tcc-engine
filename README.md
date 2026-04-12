# basilio-soar

Plataforma SOAR (Security Orchestration, Automation and Response) para apoio a resposta a incidentes de seguranca.

## Stack

- Django + DRF
- Channels (WebSocket)
- Celery + Redis
- PostgreSQL
- Docker Compose

## Requisitos

- Docker
- Docker Compose
- Python 3.12+ para execucao local sem Docker

## Configuracao

1. Na pasta `Soar`, copie o arquivo de exemplo:

```powershell
Copy-Item .env.exemple .env
```

2. Ajuste os valores no `.env` conforme seu ambiente.

Para desenvolvimento local sem Docker, existe um arquivo de apoio `.env.dev` com SQLite, Celery eager e Channels em memoria.

## Subir ambiente (Docker)

Na pasta `Soar`:

```powershell
docker compose up --build
```

Servicos principais:

- `web` (Django + Daphne)
- `worker` (Celery worker)
- `beat` (Celery beat)
- `redis`
- `db` (PostgreSQL)
- `flower` (monitoramento do Celery)

## URLs

- Web UI: `http://localhost:8000/`
- API Docs (Swagger): `http://localhost:8000/api/docs/`
- OpenAPI Schema: `http://localhost:8000/api/schema/`
- Flower: `http://localhost:5555/`

## Execucao local sem Docker

Na pasta `Soar`:

1. Criar e ativar o ambiente virtual:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

2. Usar a configuracao local:

```powershell
Copy-Item .env.dev .env
```

3. Aplicar migracoes:

```powershell
python manage.py migrate
```

4. Subir a aplicacao com ASGI:

```powershell
.venv\Scripts\daphne.exe -b 127.0.0.1 -p 8000 core.asgi:application
```

URLs locais:

- Web UI: `http://127.0.0.1:8000/`
- API Docs (Swagger): `http://127.0.0.1:8000/api/docs/`

Observacoes importantes:

- Para este projeto, prefira `daphne` em vez de `python manage.py runserver`.
- A UI abre conexoes WebSocket em `/ws/notify/` e `/ws/incidents/<id>/`.
- Com `runserver`, a parte HTTP funciona, mas os WebSockets podem responder `404`, gerando ruido no terminal e desabilitando atualizacoes em tempo real.
- Com `.env.dev`, Celery roda em modo eager, entao nao e necessario subir `worker`, `beat`, `redis` ou `postgres` para validar a engine localmente.
- Com `.env.dev`, Redis local em `127.0.0.1:6379` passa a ser obrigatorio para broker, channel layer, cache de triggers e deduplicacao.

## Comandos uteis

Rodar migracoes:

```powershell
docker compose exec web python manage.py migrate
```

Criar superusuario:

```powershell
docker compose exec web python manage.py createsuperuser
```

Popular dados demo:

```powershell
docker compose exec web python manage.py seed_demo
```

Validar projeto:

```powershell
docker compose exec web python manage.py check
docker compose exec web python manage.py test
```

Validar localmente sem Docker:

```powershell
python manage.py check
python manage.py test
```

Parar ambiente:

```powershell
docker compose down
```

## Credenciais demo (seed_demo)

- `admin / admin123`
- `soclead / soclead123`
- `analyst / analyst123`

## Observacoes

- Para execucoes assicronas reais de playbook, mantenha `CELERY_TASK_ALWAYS_EAGER=False`.
- Para usar enriquecimento VirusTotal, configure `VIRUSTOTAL_API_KEY`.
- A exportacao de PDF exige `WeasyPrint` funcional com as bibliotecas nativas do sistema. Sem isso, a aplicacao nao sobe corretamente.
- Configure `CACHE_URL`, `REDIS_URL` ou `CELERY_BROKER_URL` com Redis valido. Sem isso, a aplicacao falha no boot porque cache compartilhado para triggers e deduplicacao e obrigatorio.

## Playbooks

O modulo de playbooks implementa uma engine declarativa simples para automacao e orquestracao
de acoes sobre incidentes e artefatos.

### DSL suportada

Campos principais:

- `name`
- `description`
- `type`: `incident` ou `artifact`
- `mode`: `automatic` ou `manual`
- `triggers`: obrigatorio para playbooks automaticos
- `filters`: obrigatorio para playbooks manuais
- `steps`
- `on_error`: `stop` ou `continue`

Cada passo aceita:

- `name`
- `action`
- `input`
- `when` (opcional)

### Eventos automaticos suportados

- `incident.created`
- `incident.updated`
- `artifact.created`

### Filtros suportados

Filtros de trigger para incidentes:

- `labels`
- `any_label`
- `status`
- `severity`
- `assignee`
- `changed_fields`

Filtros de trigger para artefatos:

- `type`
- `value_contains`
- `incident_labels`
- `attribute_equals`

Filtros manuais reutilizam a mesma ideia por meio de `conditions`, com alvo `incident` ou `artifact`.

### Modelo de execucao

- A execucao e linear: os `steps` sao processados em sequencia.
- Nao ha loops, retries, timeouts, aprovacoes humanas ou pausa/retomada nativa.
- Passos podem ser ignorados com condicionais simples via `when`.
- `on_error: "stop"` interrompe no primeiro erro.
- `on_error: "continue"` registra a falha e segue para o proximo passo.

Contexto disponivel em runtime:

- `incident`
- `execution`
- `actor`
- `results`
- `trigger_context`
- `artifact` e `artifact_instance` para playbooks do tipo `artifact`, quando aplicavel

### Integracoes e limitacoes atuais

- Os conectores HTTP do VirusTotal exigem `VIRUSTOTAL_API_KEY` e conectividade com a API real. Sem isso, os playbooks que dependem desses conectores falham explicitamente.
- A DSL interpreta placeholders simples em `input`, como `{{incident.id}}`, `{{artifact.value}}`, `{{trigger_context.event}}` e `{{results.step_name.field}}`.
- O suporte atual cobre navegacao por caminho com ponto dentro de strings, listas e objetos JSON.
- Tambem sao suportados filtros simples em pipeline, como `default`, `lower`, `upper`, `strip`, `length`, `json` e `join`.
- Exemplo: `{{incident.assignee.username|default:"unassigned"|upper}}`.
- Placeholders tambem podem ser usados em `triggers` e `filters`. Nesses casos, sao resolvidos contra o payload do evento ou contra o incidente/artefato avaliado.
- O campo `when` aceita condicionais simples como `equals`, `not_equals`, `in`, `contains`, `exists`, `all`, `any` e `not`.
- Ainda nao ha expressoes arbitrarias, templates condicionais ou filtros customizados por playbook.

### Validacao e execucao

- A DSL pode ser validada na UI de playbooks ou pelo endpoint `POST /api/v1/playbooks/validate/`.
- Playbooks manuais podem ser disparados pela UI ou pela API.
- Playbooks automaticos sao disparados pelos sinais de incidente e artefato.
