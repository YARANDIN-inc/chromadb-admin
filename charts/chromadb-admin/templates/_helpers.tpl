{{/*
Expand the name of the chart.
*/}}
{{- define "chromadb-admin.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "chromadb-admin.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "chromadb-admin.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "chromadb-admin.labels" -}}
helm.sh/chart: {{ include "chromadb-admin.chart" . }}
{{ include "chromadb-admin.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "chromadb-admin.selectorLabels" -}}
app.kubernetes.io/name: {{ include "chromadb-admin.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ChromaDB Admin labels
*/}}
{{- define "chromadb-admin.chromadbAdminLabels" -}}
{{ include "chromadb-admin.labels" . }}
app.kubernetes.io/component: web
{{- end }}

{{/*
ChromaDB Admin selector labels
*/}}
{{- define "chromadb-admin.chromadbAdminSelectorLabels" -}}
{{ include "chromadb-admin.selectorLabels" . }}
app.kubernetes.io/component: web
{{- end }}

{{/*
ChromaDB labels
*/}}
{{- define "chromadb-admin.chromadbLabels" -}}
{{ include "chromadb-admin.labels" . }}
app.kubernetes.io/component: chromadb
{{- end }}

{{/*
ChromaDB selector labels
*/}}
{{- define "chromadb-admin.chromadbSelectorLabels" -}}
{{ include "chromadb-admin.selectorLabels" . }}
app.kubernetes.io/component: chromadb
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "chromadb-admin.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "chromadb-admin.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the ChromaDB Admin image name
*/}}
{{- define "chromadb-admin.chromadbAdminImage" -}}
{{- $registry := .Values.global.imageRegistry | default .Values.chromadbAdmin.image.registry }}
{{- $repository := .Values.chromadbAdmin.image.repository }}
{{- $tag := .Values.chromadbAdmin.image.tag | default .Chart.AppVersion }}
{{- if $registry }}
{{- printf "%s/%s:%s" $registry $repository $tag }}
{{- else }}
{{- printf "%s:%s" $repository $tag }}
{{- end }}
{{- end }}

{{/*
Create the ChromaDB image name
*/}}
{{- define "chromadb-admin.chromadbImage" -}}
{{- $registry := .Values.global.imageRegistry | default .Values.chromadb.image.registry }}
{{- $repository := .Values.chromadb.image.repository }}
{{- $tag := .Values.chromadb.image.tag }}
{{- if $registry }}
{{- printf "%s/%s:%s" $registry $repository $tag }}
{{- else }}
{{- printf "%s:%s" $repository $tag }}
{{- end }}
{{- end }}

{{/*
Generate the database URL
*/}}
{{- define "chromadb-admin.databaseUrl" -}}
{{- if .Values.chromadbAdmin.config.databaseUrl }}
{{- .Values.chromadbAdmin.config.databaseUrl }}
{{- else if .Values.postgresql.enabled }}
{{- $host := printf "%s-postgresql" (include "chromadb-admin.fullname" .) }}
{{- $port := "5432" }}
{{- $database := .Values.postgresql.auth.database }}
{{- $username := .Values.postgresql.auth.username }}
{{- printf "postgresql://%s:$(POSTGRES_PASSWORD)@%s:%s/%s" $username $host $port $database }}
{{- else }}
{{- fail "Database URL must be provided when external PostgreSQL is used" }}
{{- end }}
{{- end }}

{{/*
Generate the ChromaDB URL
*/}}
{{- define "chromadb-admin.chromadbUrl" -}}
{{- if .Values.chromadbAdmin.config.chromadbUrl }}
{{- .Values.chromadbAdmin.config.chromadbUrl }}
{{- else if .Values.chromadb.enabled }}
{{- $host := printf "%s-chromadb" (include "chromadb-admin.fullname" .) }}
{{- $port := .Values.chromadb.service.port }}
{{- printf "http://%s:%v" $host $port }}
{{- else }}
{{- fail "ChromaDB URL must be provided when external ChromaDB is used" }}
{{- end }}
{{- end }}

{{/*
Generate a secret key if not provided
*/}}
{{- define "chromadb-admin.secretKey" -}}
{{- if .Values.chromadbAdmin.config.secretKey }}
{{- .Values.chromadbAdmin.config.secretKey }}
{{- else }}
{{- randAlphaNum 32 }}
{{- end }}
{{- end }}

{{/*
Generate initial admin password if not provided
*/}}
{{- define "chromadb-admin.initialAdminPassword" -}}
{{- if .Values.chromadbAdmin.config.initialAdmin.password }}
{{- .Values.chromadbAdmin.config.initialAdmin.password }}
{{- else }}
{{- randAlphaNum 16 }}
{{- end }}
{{- end }}

{{/*
Get the secret name to use for environment variables
*/}}
{{- define "chromadb-admin.secretName" -}}
{{- if .Values.chromadbAdmin.config.existingSecret.enabled }}
{{- .Values.chromadbAdmin.config.existingSecret.secretName }}
{{- else }}
{{- include "chromadb-admin.fullname" . }}-secret
{{- end }}
{{- end }} 