{{- define "promptlatch.name" -}}
promptlatch
{{- end -}}

{{- define "promptlatch.fullname" -}}
{{- if .Values.migration.preserveLegacyNames -}}
{{- if contains "promptcloak" .Release.Name -}}
{{ .Release.Name }}
{{- else -}}
{{ .Release.Name }}-promptcloak
{{- end -}}
{{- else if contains (include "promptlatch.name" .) .Release.Name -}}
{{ .Release.Name }}
{{- else -}}
{{ .Release.Name }}-{{ include "promptlatch.name" . }}
{{- end -}}
{{- end -}}

{{- define "promptlatch.selectorName" -}}
{{- if .Values.migration.preserveLegacyNames -}}
promptcloak
{{- else -}}
{{ include "promptlatch.name" . }}
{{- end -}}
{{- end -}}

{{- define "promptlatch.secretName" -}}
{{- if .Values.existingSecret -}}
{{ .Values.existingSecret }}
{{- else -}}
{{ include "promptlatch.fullname" . }}-secret
{{- end -}}
{{- end -}}

{{- define "promptlatch.serverApiKey" -}}
{{- if .Values.serverAuth.apiKey -}}
{{- .Values.serverAuth.apiKey -}}
{{- else if hasKey .Values.secretEnv "PROMPTLATCH_SERVER_API_KEY" -}}
{{- index .Values.secretEnv "PROMPTLATCH_SERVER_API_KEY" -}}
{{- else if hasKey .Values.secretEnv "PROMPTCLOAK_SERVER_API_KEY" -}}
{{- index .Values.secretEnv "PROMPTCLOAK_SERVER_API_KEY" -}}
{{- else -}}
{{- $secretName := include "promptlatch.secretName" . -}}
{{- $existing := lookup "v1" "Secret" .Release.Namespace $secretName -}}
{{- if and $existing (hasKey $existing.data "PROMPTLATCH_SERVER_API_KEY") -}}
{{- index $existing.data "PROMPTLATCH_SERVER_API_KEY" | b64dec -}}
{{- else if and $existing (hasKey $existing.data "PROMPTCLOAK_SERVER_API_KEY") -}}
{{- index $existing.data "PROMPTCLOAK_SERVER_API_KEY" | b64dec -}}
{{- else -}}
{{- randAlphaNum 48 -}}
{{- end -}}
{{- end -}}
{{- end -}}
