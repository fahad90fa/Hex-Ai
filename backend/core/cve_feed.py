# language: Python, file: backend/core/cve_feed.py
# NVD API v2 integration with aiohttp, Redis cache TTL 24h, search_cve(keyword, cpe) -> list[CVEResult]
import json
import logging
from dataclasses import dataclass, field
from typing import Optional

import aiohttp
import redis.asyncio as aioredis

from ..config import get_settings

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL_SECONDS = 86400  # 24 hours
_cve_feed: "CVEFeed | None" = None


@dataclass
class CVEResult:
    id: str
    description: str
    cvss_score: float
    cvss_vector: str
    published: str
    last_modified: str
    cve_id: str
    has_exploit: bool = False
    references: list[str] = field(default_factory=list)
    affected_products: list[str] = field(default_factory=list)


class CVEFeed:
    def __init__(self):
        self._redis: aioredis.Redis | None = None
        self._session: aiohttp.ClientSession | None = None

    async def startup(self):
        self._redis = await aioredis.from_url(get_settings().redis_url, decode_responses=True)
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={"User-Agent": "NEXUS-PenTest-Framework/1.0"},
        )

    async def shutdown(self):
        if self._session:
            await self._session.close()
        if self._redis:
            await self._redis.aclose()

    def _cache_key(self, keyword: str, cpe: Optional[str]) -> str:
        return f"nexus:cve:{keyword}:{cpe or ''}".replace(" ", "_")

    async def search_cve(
        self,
        keyword: str,
        cpe: Optional[str] = None,
        results_per_page: int = 20,
    ) -> list[CVEResult]:
        """Search NVD for CVEs matching keyword and/or CPE. Returns cached results if available."""
        cache_key = self._cache_key(keyword, cpe)

        # Check cache
        if self._redis:
            cached = await self._redis.get(cache_key)
            if cached:
                try:
                    raw_list = json.loads(cached)
                    return [CVEResult(**item) for item in raw_list]
                except Exception:
                    pass

        results = await self._fetch_nvd(keyword=keyword, cpe=cpe, results_per_page=results_per_page)

        # Cache results
        if self._redis and results:
            try:
                serialized = json.dumps([
                    {
                        "id": r.id,
                        "description": r.description,
                        "cvss_score": r.cvss_score,
                        "cvss_vector": r.cvss_vector,
                        "published": r.published,
                        "last_modified": r.last_modified,
                        "cve_id": r.cve_id,
                        "has_exploit": r.has_exploit,
                        "references": r.references,
                        "affected_products": r.affected_products,
                    }
                    for r in results
                ])
                await self._redis.setex(cache_key, CACHE_TTL_SECONDS, serialized)
            except Exception as e:
                logger.warning(f"CVE cache write error: {e}")

        return results

    async def _fetch_nvd(
        self,
        keyword: str,
        cpe: Optional[str],
        results_per_page: int,
    ) -> list[CVEResult]:
        """Fetch CVEs from NVD API v2."""
        params: dict = {
            "resultsPerPage": results_per_page,
            "startIndex": 0,
        }
        if keyword:
            params["keywordSearch"] = keyword
        if cpe:
            params["cpeName"] = cpe

        results: list[CVEResult] = []

        if not self._session:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
            )

        try:
            async with self._session.get(NVD_API_BASE, params=params) as resp:
                if resp.status != 200:
                    logger.warning(f"NVD API returned {resp.status} for keyword={keyword}")
                    return []
                data = await resp.json(content_type=None)

                for item in data.get("vulnerabilities", []):
                    cve_data = item.get("cve", {})
                    cve_id = cve_data.get("id", "")
                    published = cve_data.get("published", "")
                    last_modified = cve_data.get("lastModified", "")

                    # description
                    descriptions = cve_data.get("descriptions", [])
                    description = next(
                        (d["value"] for d in descriptions if d.get("lang") == "en"),
                        "",
                    )

                    # CVSS score
                    cvss_score = 0.0
                    cvss_vector = ""
                    metrics = cve_data.get("metrics", {})
                    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        metric_list = metrics.get(metric_key, [])
                        if metric_list:
                            cvss_data = metric_list[0].get("cvssData", {})
                            cvss_score = float(cvss_data.get("baseScore", 0.0))
                            cvss_vector = cvss_data.get("vectorString", "")
                            break

                    # references
                    references = [
                        r.get("url", "") for r in cve_data.get("references", [])
                    ]
                    has_exploit = any(
                        "exploit" in r.lower() or "github.com" in r.lower()
                        for r in references
                    )

                    # affected products
                    affected_products: list[str] = []
                    for config in cve_data.get("configurations", []):
                        for node in config.get("nodes", []):
                            for cpe_match in node.get("cpeMatch", []):
                                if cpe_match.get("vulnerable"):
                                    affected_products.append(cpe_match.get("criteria", ""))

                    results.append(CVEResult(
                        id=cve_id,
                        cve_id=cve_id,
                        description=description,
                        cvss_score=cvss_score,
                        cvss_vector=cvss_vector,
                        published=published,
                        last_modified=last_modified,
                        references=references[:10],
                        has_exploit=has_exploit,
                        affected_products=affected_products[:20],
                    ))

        except aiohttp.ClientError as e:
            logger.error(f"NVD API request error: {e}")
        except Exception as e:
            logger.error(f"NVD parse error: {e}")

        return results


def get_cve_feed() -> CVEFeed:
    global _cve_feed
    if _cve_feed is None:
        _cve_feed = CVEFeed()
    return _cve_feed
