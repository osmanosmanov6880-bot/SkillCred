"""Small deterministic locale catalog for human-readable CLI/API messages."""

from __future__ import annotations

import os

MESSAGES: dict[str, dict[str, str]] = {
    "en": {
        "issued": "Issued credential to {path} (id: {id})",
        "wallet_created": "Encrypted wallet created",
        "wallet_exists": "Wallet already exists: {path}; choose another path",
        "passphrase_short": "Use a wallet passphrase of at least 12 characters",
        "wallet_copied": "Encrypted wallet copied to {path}",
        "status_written": "Signed status list written to {path}",
        "revoked": "Revoked status-list index {index}; publish an updated list before relying on it.",
        "bearer_required": "Bearer token required",
        "bad_token": "Invalid bearer token",
        "role_denied": "Insufficient role",
        "rate_limit": "Rate limit exceeded",
    },
    "ru": {
        "issued": "Подтверждение выдано: {path} (идентификатор: {id})",
        "wallet_created": "Зашифрованный кошелёк создан",
        "wallet_exists": "Кошелёк уже существует: {path}; укажите другой путь",
        "passphrase_short": "Парольная фраза кошелька должна содержать не менее 12 символов",
        "wallet_copied": "Зашифрованная копия кошелька сохранена: {path}",
        "status_written": "Подписанный список статусов сохранён: {path}",
        "revoked": "Индекс списка статусов {index} отозван; перед проверкой опубликуйте обновлённый список.",
        "bearer_required": "Требуется Bearer-токен",
        "bad_token": "Неверный Bearer-токен",
        "role_denied": "Недостаточно прав для операции",
        "rate_limit": "Превышен лимит запросов",
    },
    "de": {
        "issued": "Nachweis ausgegeben: {path} (ID: {id})",
        "wallet_created": "Verschlüsselte Wallet erstellt",
        "wallet_exists": "Wallet existiert bereits: {path}; wählen Sie einen anderen Pfad",
        "passphrase_short": "Die Passphrase muss mindestens 12 Zeichen haben",
        "wallet_copied": "Verschlüsselte Wallet kopiert nach {path}",
        "status_written": "Signierte Statusliste gespeichert: {path}",
        "revoked": "Statuslistenindex {index} widerrufen; veröffentlichen Sie vor der Prüfung eine aktualisierte Liste.",
        "bearer_required": "Bearer-Token erforderlich",
        "bad_token": "Ungültiges Bearer-Token",
        "role_denied": "Unzureichende Berechtigung",
        "rate_limit": "Anfragelimit überschritten",
    },
    "fr": {
        "issued": "Attestation émise : {path} (id : {id})",
        "wallet_created": "Portefeuille chiffré créé",
        "wallet_exists": "Le portefeuille existe déjà : {path} ; choisissez un autre chemin",
        "passphrase_short": "La phrase secrète doit contenir au moins 12 caractères",
        "wallet_copied": "Portefeuille chiffré copié vers {path}",
        "status_written": "Liste d’état signée enregistrée : {path}",
        "revoked": "Index de liste d’état {index} révoqué ; publiez une liste mise à jour avant toute vérification.",
        "bearer_required": "Jeton Bearer requis",
        "bad_token": "Jeton Bearer invalide",
        "role_denied": "Rôle insuffisant",
        "rate_limit": "Limite de requêtes dépassée",
    },
    "es": {
        "issued": "Credencial emitida: {path} (id: {id})",
        "wallet_created": "Cartera cifrada creada",
        "wallet_exists": "La cartera ya existe: {path}; elija otra ruta",
        "passphrase_short": "La frase de contraseña debe tener al menos 12 caracteres",
        "wallet_copied": "Cartera cifrada copiada a {path}",
        "status_written": "Lista de estado firmada guardada en {path}",
        "revoked": "Índice de lista de estado {index} revocado; publique una lista actualizada antes de verificar.",
        "bearer_required": "Se requiere un token Bearer",
        "bad_token": "Token Bearer no válido",
        "role_denied": "Permisos insuficientes",
        "rate_limit": "Se excedió el límite de solicitudes",
    },
    "zh": {
        "issued": "凭证已签发：{path}（编号：{id}）",
        "wallet_created": "已创建加密钱包",
        "wallet_exists": "钱包已存在：{path}；请选择其他路径",
        "passphrase_short": "口令至少需要 12 个字符",
        "wallet_copied": "加密钱包已复制到 {path}",
        "status_written": "已保存签名状态列表：{path}",
        "revoked": "状态列表索引 {index} 已撤销；验证前请发布更新后的列表。",
        "bearer_required": "需要 Bearer 令牌",
        "bad_token": "Bearer 令牌无效",
        "role_denied": "权限不足",
        "rate_limit": "请求次数超过限制",
    },
    "ar": {
        "issued": "تم إصدار بيانات الاعتماد إلى {path} (المعرّف: {id})",
        "wallet_created": "تم إنشاء محفظة مشفّرة",
        "wallet_exists": "المحفظة موجودة بالفعل: {path}؛ اختر مساراً آخر",
        "passphrase_short": "يجب ألا تقل عبارة المرور عن 12 حرفاً",
        "wallet_copied": "تم نسخ المحفظة المشفّرة إلى {path}",
        "status_written": "تم حفظ قائمة الحالة الموقعة في {path}",
        "revoked": "تم إلغاء فهرس قائمة الحالة {index}؛ انشر قائمة محدثة قبل التحقق.",
        "bearer_required": "مطلوب رمز Bearer",
        "bad_token": "رمز Bearer غير صالح",
        "role_denied": "صلاحيات غير كافية",
        "rate_limit": "تم تجاوز حد الطلبات",
    },
}
SUPPORTED_LANGUAGES = frozenset(MESSAGES)
RTL_LANGUAGES = frozenset({"ar"})


def normalize_language(value: str | None) -> str:
    candidate = (value or os.getenv("SKILLCRED_LANG", "en")).strip().lower().replace("_", "-")
    primary = candidate.split("-", 1)[0]
    return primary if primary in SUPPORTED_LANGUAGES else "en"


def is_rtl(language: str | None) -> bool:
    return normalize_language(language) in RTL_LANGUAGES


def translate(key: str, language: str | None = None, **values: object) -> str:
    lang = normalize_language(language)
    template = MESSAGES.get(lang, MESSAGES["en"]).get(key, MESSAGES["en"].get(key, key))
    return template.format(**values)


def language_from_accept_header(header: str | None) -> str:
    if not header:
        return normalize_language(None)
    candidates: list[tuple[float, int, str]] = []
    for index, item in enumerate(header.split(",")):
        parts = [part.strip() for part in item.split(";")]
        lang = normalize_language(parts[0])
        quality = 1.0
        for param in parts[1:]:
            if param.startswith("q="):
                try:
                    quality = float(param[2:])
                except ValueError:
                    quality = 0.0
        if quality > 0:
            candidates.append((quality, -index, lang))
    return max(candidates)[2] if candidates else "en"
