"""NLP-based MITRE ATT&CK mapper using sentence transformers.

Implements semantic similarity-based mapping as designed in 05-MAPPING-AGENT.md.
Uses sentence transformers (all-MiniLM-L6-v2) for lightweight, CPU-friendly embeddings.
"""

import hashlib
import json
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import numpy as np
import structlog

from app.models.detection_mapping import MappingSource

logger = structlog.get_logger()


@dataclass
class NLPMappingResult:
    """Result of NLP-based detection-to-technique mapping."""

    technique_id: str
    technique_name: str
    confidence: float
    similarity_score: float
    rationale: str
    mapping_source: MappingSource = MappingSource.NLP


class MITREEmbeddingsCache:
    """Cache for pre-computed MITRE technique embeddings.

    Stores embeddings in a file cache to avoid recomputing on every startup.
    Embeddings are versioned by MITRE framework version and model name.
    """

    def __init__(
        self,
        cache_dir: Optional[str] = None,
        mitre_version: str = "14.1",
        model_name: str = "all-MiniLM-L6-v2",
    ):
        # Use system temp directory instead of hardcoded /tmp for security
        if cache_dir is None:
            cache_dir = str(Path(tempfile.gettempdir()) / "a13e_embeddings_cache")
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.mitre_version = mitre_version
        self.model_name = model_name
        self._embeddings: Optional[dict[str, np.ndarray]] = None
        self._technique_metadata: Optional[dict[str, dict]] = None
        self.logger = logger.bind(component="MITREEmbeddingsCache")

    @property
    def cache_file(self) -> Path:
        """Path to the embeddings cache file."""
        cache_key = f"{self.mitre_version}_{self.model_name}"
        cache_hash = hashlib.sha256(cache_key.encode()).hexdigest()[:8]
        return self.cache_dir / f"mitre_embeddings_{cache_hash}.npz"

    @property
    def metadata_file(self) -> Path:
        """Path to the technique metadata file."""
        cache_key = f"{self.mitre_version}_{self.model_name}"
        cache_hash = hashlib.sha256(cache_key.encode()).hexdigest()[:8]
        return self.cache_dir / f"mitre_metadata_{cache_hash}.json"

    def load_or_compute(
        self, techniques: list[dict]
    ) -> tuple[dict[str, np.ndarray], dict[str, dict]]:
        """Load embeddings from cache or compute if not available."""
        if self._embeddings is not None and self._technique_metadata is not None:
            return self._embeddings, self._technique_metadata

        # Try loading from cache
        if self.cache_file.exists() and self.metadata_file.exists():
            try:
                self._embeddings, self._technique_metadata = self._load_from_cache()
                self.logger.info(
                    "embeddings_loaded_from_cache",
                    technique_count=len(self._embeddings),
                )
                return self._embeddings, self._technique_metadata
            except Exception as e:
                self.logger.warning("cache_load_failed", error=str(e))

        # Compute embeddings
        self._embeddings, self._technique_metadata = self._compute_embeddings(
            techniques
        )
        self._save_to_cache()
        return self._embeddings, self._technique_metadata

    def _load_from_cache(self) -> tuple[dict[str, np.ndarray], dict[str, dict]]:
        """Load embeddings from cache files."""
        # Load embeddings
        data = np.load(str(self.cache_file), allow_pickle=True)
        technique_ids = data["technique_ids"].tolist()
        embeddings_array = data["embeddings"]

        embeddings = {tid: embeddings_array[i] for i, tid in enumerate(technique_ids)}

        # Load metadata
        with open(self.metadata_file, "r") as f:
            metadata = json.load(f)

        return embeddings, metadata

    def _compute_embeddings(
        self, techniques: list[dict]
    ) -> tuple[dict[str, np.ndarray], dict[str, dict]]:
        """Compute embeddings for all MITRE techniques."""
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError:
            self.logger.error("sentence_transformers_not_installed")
            return {}, {}

        self.logger.info("computing_embeddings", model=self.model_name)

        model = SentenceTransformer(self.model_name)
        embeddings = {}
        metadata = {}

        for technique in techniques:
            technique_id = technique.get("technique_id")
            if not technique_id:
                continue

            # Build text for embedding
            text = self._build_technique_text(technique)

            # Compute embedding
            embedding = model.encode(text, convert_to_numpy=True)
            embeddings[technique_id] = embedding

            # Store metadata
            metadata[technique_id] = {
                "name": technique.get("name", ""),
                "tactic_id": technique.get("tactic_id", ""),
                "tactic_name": technique.get("tactic_name", ""),
                "description": technique.get("description", "")[
                    :500
                ],  # Truncate for storage
                "platforms": technique.get("platforms", []),
            }

        self.logger.info("embeddings_computed", technique_count=len(embeddings))
        return embeddings, metadata

    def _build_technique_text(self, technique: dict) -> str:
        """Build text representation of a technique for embedding."""
        parts = [
            technique.get("name", ""),
            technique.get("description", ""),
            technique.get("detection_guidance", ""),
        ]

        # Add data sources
        data_sources = technique.get("data_sources", [])
        if data_sources:
            parts.append(f"Data sources: {', '.join(data_sources)}")

        # Add platforms
        platforms = technique.get("platforms", [])
        if platforms:
            parts.append(f"Platforms: {', '.join(platforms)}")

        return " ".join(filter(None, parts))

    def _save_to_cache(self):
        """Save embeddings to cache files."""
        if not self._embeddings or not self._technique_metadata:
            return

        try:
            # Save embeddings as numpy array
            technique_ids = list(self._embeddings.keys())
            embeddings_array = np.array(
                [self._embeddings[tid] for tid in technique_ids]
            )

            np.savez(
                str(self.cache_file),
                technique_ids=np.array(technique_ids),
                embeddings=embeddings_array,
            )

            # Save metadata as JSON
            with open(self.metadata_file, "w") as f:
                json.dump(self._technique_metadata, f)

            self.logger.info("embeddings_saved_to_cache", path=str(self.cache_file))
        except Exception as e:
            self.logger.error("cache_save_failed", error=str(e))

    def invalidate(self):
        """Invalidate the cache."""
        self._embeddings = None
        self._technique_metadata = None
        if self.cache_file.exists():
            self.cache_file.unlink()
        if self.metadata_file.exists():
            self.metadata_file.unlink()


class NLPMapper:
    """NLP-based detection-to-MITRE mapper using sentence transformers.

    Uses semantic similarity between detection descriptions and MITRE technique
    descriptions to identify potential mappings.
    """

    # Confidence calibration thresholds
    HIGH_SIMILARITY_THRESHOLD = 0.8
    MEDIUM_SIMILARITY_THRESHOLD = 0.6
    LOW_SIMILARITY_THRESHOLD = 0.4

    # Confidence score mapping
    HIGH_CONFIDENCE = 0.7
    MEDIUM_CONFIDENCE = 0.55
    LOW_CONFIDENCE = 0.4

    def __init__(
        self,
        model_name: str = "all-MiniLM-L6-v2",
        mitre_version: str = "14.1",
        top_k: int = 5,
    ):
        self.model_name = model_name
        self.mitre_version = mitre_version
        self.top_k = top_k
        self._model = None
        self._embeddings_cache = MITREEmbeddingsCache(
            mitre_version=mitre_version,
            model_name=model_name,
        )
        self._embeddings: Optional[dict[str, np.ndarray]] = None
        self._technique_metadata: Optional[dict[str, dict]] = None
        self.logger = logger.bind(component="NLPMapper")

    def initialize(self, techniques: list[dict]):
        """Initialize the mapper with MITRE techniques.

        Should be called once during application startup.
        """
        self._embeddings, self._technique_metadata = (
            self._embeddings_cache.load_or_compute(techniques)
        )
        self.logger.info(
            "nlp_mapper_initialized",
            technique_count=len(self._embeddings) if self._embeddings else 0,
        )

    def _get_model(self):
        """Lazy load the sentence transformer model."""
        if self._model is None:
            try:
                from sentence_transformers import SentenceTransformer

                self._model = SentenceTransformer(self.model_name)
            except ImportError:
                self.logger.error("sentence_transformers_not_installed")
                raise RuntimeError("sentence-transformers package not installed")
        return self._model

    def map_detection(
        self,
        name: str,
        description: str = "",
        query_pattern: str = "",
        raw_config: Optional[dict] = None,
    ) -> list[NLPMappingResult]:
        """Map a detection to MITRE techniques using NLP.

        Args:
            name: Detection name
            description: Detection description
            query_pattern: Query/filter pattern
            raw_config: Raw detection configuration

        Returns:
            List of mapping results sorted by confidence (highest first)
        """
        if not self._embeddings or not self._technique_metadata:
            self.logger.warning("mapper_not_initialized")
            return []

        # Build detection text
        detection_text = self._build_detection_text(
            name, description, query_pattern, raw_config
        )

        if not detection_text.strip():
            return []

        # Compute detection embedding
        try:
            model = self._get_model()
            detection_embedding = model.encode(detection_text, convert_to_numpy=True)
        except Exception as e:
            self.logger.error("embedding_computation_failed", error=str(e))
            return []

        # Compute similarities
        results = []
        for technique_id, technique_embedding in self._embeddings.items():
            similarity = self._cosine_similarity(
                detection_embedding, technique_embedding
            )

            # Skip low similarity matches
            if similarity < self.LOW_SIMILARITY_THRESHOLD:
                continue

            metadata = self._technique_metadata.get(technique_id, {})
            confidence = self._calibrate_confidence(similarity)

            results.append(
                NLPMappingResult(
                    technique_id=technique_id,
                    technique_name=metadata.get("name", ""),
                    confidence=confidence,
                    similarity_score=float(similarity),
                    rationale=self._build_rationale(similarity, metadata),
                )
            )

        # Sort by confidence and take top_k
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results[: self.top_k]

    def _build_detection_text(
        self,
        name: str,
        description: str,
        query_pattern: str,
        raw_config: Optional[dict],
    ) -> str:
        """Build text representation of detection for embedding."""
        parts = [name]

        if description:
            parts.append(description)

        if query_pattern:
            # Extract keywords from query pattern
            keywords = self._extract_keywords_from_query(query_pattern)
            if keywords:
                parts.append(f"Query keywords: {keywords}")

        if raw_config:
            # Extract relevant fields from config
            config_text = self._extract_config_text(raw_config)
            if config_text:
                parts.append(config_text)

        return " ".join(parts)

    def _extract_keywords_from_query(self, query: str) -> str:
        """Extract security-relevant keywords from a query pattern."""
        # Common security terms to look for
        security_terms = {
            "delete",
            "create",
            "update",
            "modify",
            "remove",
            "terminate",
            "unauthorized",
            "denied",
            "failed",
            "error",
            "suspicious",
            "login",
            "authentication",
            "access",
            "permission",
            "role",
            "admin",
            "root",
            "privilege",
            "escalation",
            "credential",
            "key",
            "secret",
            "token",
            "password",
            "certificate",
            "firewall",
            "security",
            "network",
            "vpc",
            "subnet",
            "instance",
            "bucket",
            "storage",
            "database",
            "function",
        }

        # Simple keyword extraction
        words = query.lower().replace("_", " ").replace(".", " ").split()
        found_terms = [w for w in words if w in security_terms]

        return " ".join(set(found_terms))

    def _extract_config_text(self, config: dict) -> str:
        """Extract relevant text from detection config."""
        relevant_keys = ["filter", "description", "name", "eventType", "methodName"]
        parts = []

        for key in relevant_keys:
            if key in config and isinstance(config[key], str):
                parts.append(config[key])

        return " ".join(parts)

    def _cosine_similarity(self, a: np.ndarray, b: np.ndarray) -> float:
        """Compute cosine similarity between two vectors."""
        dot_product = np.dot(a, b)
        norm_a = np.linalg.norm(a)
        norm_b = np.linalg.norm(b)

        if norm_a == 0 or norm_b == 0:
            return 0.0

        return dot_product / (norm_a * norm_b)

    def _calibrate_confidence(self, similarity: float) -> float:
        """Calibrate confidence score based on similarity.

        NLP confidence is intentionally lower than pattern matching
        to reflect the inherent uncertainty in semantic matching.
        """
        if similarity >= self.HIGH_SIMILARITY_THRESHOLD:
            return self.HIGH_CONFIDENCE
        elif similarity >= self.MEDIUM_SIMILARITY_THRESHOLD:
            # Linear interpolation between medium and high
            ratio = (similarity - self.MEDIUM_SIMILARITY_THRESHOLD) / (
                self.HIGH_SIMILARITY_THRESHOLD - self.MEDIUM_SIMILARITY_THRESHOLD
            )
            return self.MEDIUM_CONFIDENCE + ratio * (
                self.HIGH_CONFIDENCE - self.MEDIUM_CONFIDENCE
            )
        else:
            # Linear interpolation between low and medium
            ratio = (similarity - self.LOW_SIMILARITY_THRESHOLD) / (
                self.MEDIUM_SIMILARITY_THRESHOLD - self.LOW_SIMILARITY_THRESHOLD
            )
            return self.LOW_CONFIDENCE + ratio * (
                self.MEDIUM_CONFIDENCE - self.LOW_CONFIDENCE
            )

    def _build_rationale(self, similarity: float, metadata: dict) -> str:
        """Build explanation for the mapping."""
        technique_name = metadata.get("name", "Unknown")
        tactic_name = metadata.get("tactic_name", "Unknown")

        confidence_level = (
            "high"
            if similarity >= self.HIGH_SIMILARITY_THRESHOLD
            else "medium" if similarity >= self.MEDIUM_SIMILARITY_THRESHOLD else "low"
        )

        return (
            f"NLP semantic similarity ({confidence_level} confidence): "
            f"Detection description matches {technique_name} ({tactic_name}) "
            f"with similarity score {similarity:.2f}"
        )
