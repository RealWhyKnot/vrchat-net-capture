#!/usr/bin/env bash
set -euo pipefail
shopt -s inherit_errexit

root=$(git rev-parse --show-toplevel)
cd "${root}"

require_tool() {
  if ! command -v "${1}" >/dev/null; then
    printf '%s is missing. Install it and add it to PATH.\n' "${1}" >&2
    exit 1
  fi
}

classify_path() {
  local path=${1} entry found=false
  for entry in "${vendored[@]}"; do
    case ${entry} in
      /*/) [[ ${path} != "${entry:1}"* ]] || found=true ;;
      /*) [[ ${path} != "${entry:1}" ]] || found=true ;;
      */) [[ /${path} != *"/${entry}"* ]] || found=true ;;
      *)
        printf 'Invalid vendored path: %s. Run Install-Lint again.\n' "${entry}" >&2
        exit 1
        ;;
    esac
  done
  printf '%s\n' "${found}"
}

if [[ ! -f .github/lint/vendored-paths.txt ]]; then
  printf '.github/lint/vendored-paths.txt is missing. Run Install-Lint again.\n' >&2
  exit 1
fi
vendored=()
while IFS= read -r entry || [[ -n ${entry} ]]; do
  entry=${entry%$'\r'}
  [[ -z ${entry} ]] || vendored+=("${entry}")
done <.github/lint/vendored-paths.txt
workflows=() actions=() manifests=()
files=$(mktemp)
scan_directory=''
trap 'rm -f -- "${files}"; if [[ -n ${scan_directory} ]]; then rm -rf -- "${scan_directory}"; fi' EXIT
git ls-files --cached --others --exclude-standard -z >"${files}"
while IFS= read -r -d '' file; do
  vendored_file=$(classify_path "${file}")
  if [[ ! -f ${file} || ${vendored_file} == true ]]; then
    continue
  fi
  case ${file} in
    .github/workflows/*.yml | .github/workflows/*.yaml) workflows+=("${file}") ;;
    action.yml | */action.yml | action.yaml | */action.yaml) actions+=("${file}") ;;
    Cargo.toml | */Cargo.toml) manifests+=("${file}") ;;
    *) ;;
  esac
done <"${files}"
require_tool typos
require_tool gitleaks
typos --config .github/lint/typos.toml
if ((${#workflows[@]} > 0)); then
  require_tool actionlint
  actionlint "${workflows[@]}"
fi
if ((${#workflows[@]} + ${#actions[@]} > 0)); then
  require_tool zizmor
  zizmor --offline --strict-collection --config .github/zizmor.yml "${workflows[@]}" "${actions[@]}"
fi
leak_options=(--config "${root}/.github/lint/gitleaks.toml" --no-banner --redact --verbose
  --ignore-gitleaks-allow --gitleaks-ignore-path /dev/null)
if [[ ${CI:-false} == true ]]; then
  scan_directory=$(mktemp -d)
  git ls-files --cached -z >"${files}"
  while IFS= read -r -d '' file; do
    vendored_file=$(classify_path "${file}")
    if [[ -f ${file} && ! -L ${file} && ${vendored_file} == false ]]; then
      cp --parents -- "${file}" "${scan_directory}"
    fi
  done <"${files}"
  gitleaks dir "${leak_options[@]}" "${scan_directory}"
else
  gitleaks git "${leak_options[@]}" --log-opts="--branches --not --remotes" .
fi
declare -A checked=()
for manifest in "${manifests[@]}"; do
  require_tool cargo
  require_tool cargo-deny
  workspace=$(cargo locate-project --workspace --message-format plain --manifest-path "${manifest}")
  if [[ -z ${checked[${workspace}]:-} ]]; then
    cargo deny --manifest-path "${workspace}" --workspace --config "${root}/.github/lint/deny.toml" check
    checked[${workspace}]=1
  fi
done
