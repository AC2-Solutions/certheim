{{- define "certheim.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "certheim.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "certheim.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "certheim.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "certheim.labels" -}}
helm.sh/chart: {{ include "certheim.chart" . }}
{{ include "certheim.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "certheim.selectorLabels" -}}
app.kubernetes.io/name: {{ include "certheim.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "certheim.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}

{{- define "certheim.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "certheim.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "certheim.secretName" -}}{{ include "certheim.fullname" . }}-secret{{- end -}}

{{- /* The environment shared by the app Deployment and the CronJob tasks. */ -}}
{{- define "certheim.appEnv" -}}
- name: CERTINEL_CONTAINER
  value: "1"
{{- if eq .Values.db.backend "postgres" }}
- name: CSR_DB_URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.db.postgres.existingSecret | default (include "certheim.secretName" .) }}
      key: CSR_DB_URL
{{- else }}
- name: CSR_DB_PATH
  value: /var/lib/certinel/jobs.db
{{- end }}
{{- if ne (.Values.license | default "") "" }}
- name: CSR_LICENSE_FILE
  value: /etc/certinel/secret/license
{{- end }}
{{- if .Values.openbao.enabled }}
- name: CSR_CAP_OPENBAO
  value: "1"
- name: CSR_OPENBAO_ADDR
  value: {{ .Values.openbao.addr | quote }}
- name: CSR_OPENBAO_PKI_MOUNT
  value: {{ .Values.openbao.pkiMount | quote }}
- name: CSR_OPENBAO_ROLE
  value: {{ .Values.openbao.role | quote }}
- name: CSR_OPENBAO_ROLE_ID
  valueFrom:
    secretKeyRef:
      name: {{ .Values.openbao.existingSecret | default (include "certheim.secretName" .) }}
      key: CSR_OPENBAO_ROLE_ID
- name: CSR_OPENBAO_SECRET_ID
  valueFrom:
    secretKeyRef:
      name: {{ .Values.openbao.existingSecret | default (include "certheim.secretName" .) }}
      key: CSR_OPENBAO_SECRET_ID
{{- if ne (.Values.openbao.caCert | default "") "" }}
- name: CSR_OPENBAO_CA_FILE
  value: /etc/certinel/secret/openbao-ca.pem
{{- end }}
{{- end }}
{{- range $k, $v := .Values.extraEnv }}
- name: {{ $k }}
  value: {{ $v | quote }}
{{- end }}
{{- end -}}

{{- /* True when the secret-files volume (license and/or openbao CA) is needed. */ -}}
{{- define "certheim.needSecretFiles" -}}
{{- if or (ne (.Values.license | default "") "") (and .Values.openbao.enabled (ne (.Values.openbao.caCert | default "") "")) -}}true{{- end -}}
{{- end -}}

