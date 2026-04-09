import re
import time
from typing import Dict, List, Tuple

import requests


BAIKE_API = "https://baike.baidu.com/api/lemma"
CACHE_TTL_SECONDS = 30 * 60
_entity_cache: Dict[str, Tuple[bool, float]] = {}

# Minimal stopword set for lightweight filtering.
STOPWORDS = {
    "我们",
    "你们",
    "他们",
    "这个",
    "那个",
    "这里",
    "那里",
    "一个",
    "一种",
    "一些",
    "已经",
    "因为",
    "所以",
    "如果",
    "然后",
    "就是",
    "可以",
    "没有",
    "不是",
    "还是",
    "以及",
    "进行",
}


def extract_entities(text: str) -> List[str]:
    # Extract continuous Chinese sequences (length >= 2), then filter.
    candidates = re.findall(r"[\u4e00-\u9fff]{2,}", text)
    entities: List[str] = []
    seen = set()
    for item in candidates:
        word = item.strip()
        if not word or word in STOPWORDS:
            continue
        if word not in seen:
            seen.add(word)
            entities.append(word)
    return entities


def check_entity(entity: str) -> bool:
    now = time.time()
    cached = _entity_cache.get(entity)
    if cached and now - cached[1] < CACHE_TTL_SECONDS:
        return cached[0]

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )
    }
    try:
        resp = requests.get(
            BAIKE_API,
            params={"lemma": entity},
            headers=headers,
            timeout=5,
        )
        resp.raise_for_status()
        data = resp.json()

        status = str(data.get("status", ""))
        lemma = str(data.get("lemma", "")).strip()
        ok = status in {"0", "200", "success"} and lemma != ""
    except Exception:
        ok = False

    _entity_cache[entity] = (ok, now)
    return ok


def get_cached_entity_status(entity: str) -> Tuple[bool, bool]:
    """Return (exists, cache_hit). If not in cache/expired, performs check."""
    now = time.time()
    cached = _entity_cache.get(entity)
    if cached and now - cached[1] < CACHE_TTL_SECONDS:
        return cached[0], True
    return check_entity(entity), False
