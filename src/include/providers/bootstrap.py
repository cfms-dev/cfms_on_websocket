from include.config.settings import global_config
from include.config.validation import (
    AdmissionControlPolicy,
    S3StoragePolicy,
    SchedulingPolicy,
    get_enabled_extensions,
)
from include.providers.manager import ProviderManager
from include.providers.storage import LocalStorageProvider


def initialize_providers(config=global_config) -> None:
    """
    Initialize and register the providers required by the application.
    """

    match config["provider"]["storage"]:
        case "local":
            storage_provider = LocalStorageProvider()
        case "s3":
            from include.providers.storage.s3 import S3StorageProvider

            s3_policy = S3StoragePolicy.from_config(config)
            storage_provider = S3StorageProvider(
                bucket_name=s3_policy.bucket,
                endpoint_url=s3_policy.endpoint_url,
                aws_access_key_id=s3_policy.access_key_id,
                aws_secret_access_key=s3_policy.secret_access_key,
                region_name=s3_policy.region_name,
                aws_session_token=s3_policy.session_token,
                addressing_style=s3_policy.addressing_style,
                max_pool_connections=(
                    s3_policy.max_pool_connections
                    or AdmissionControlPolicy.from_config(config).max_connections
                ),
            )
        case _:
            raise ValueError(
                f"Unsupported storage provider type: {config['provider']['storage']}"
            )

    ProviderManager().register(storage_provider)

    match config["provider"]["caching"]:
        case "memory":
            from include.providers.caching import MemoryCachingProvider

            caching_provider = MemoryCachingProvider()
        case "redis":
            from include.providers.caching import RedisCachingProvider

            redis_cfg = config["redis"]
            caching_provider = RedisCachingProvider(
                host=redis_cfg["host"],
                port=redis_cfg["port"],
                password=redis_cfg.get("password", ""),
                db=redis_cfg.get("db", 0),
            )
        case _:
            raise ValueError(
                f"Unsupported caching provider type: {config['provider']['caching']}"
            )

    ProviderManager().register(caching_provider)

    match config["provider"].get("rate_limit", "memory"):
        case "memory":
            from include.providers.rate_limits import MemoryRateLimitProvider

            rate_limit_provider = MemoryRateLimitProvider()
        case "redis":
            from include.providers.rate_limits import RedisRateLimitProvider

            redis_cfg = config["redis"]
            rate_limit_provider = RedisRateLimitProvider(
                host=redis_cfg["host"],
                port=redis_cfg.get("port", 6379),
                password=redis_cfg.get("password", ""),
                db=redis_cfg.get("db", 0),
            )
        case _:
            raise ValueError(
                "Unsupported rate-limit provider type: "
                f"{config['provider']['rate_limit']}"
            )

    ProviderManager().register(rate_limit_provider)

    match config["provider"]["event_bus"]:
        case "local":
            from include.providers.events import LocalEventBusProvider

            event_bus_provider = LocalEventBusProvider()
        case "redis":
            from include.providers.events import RedisEventBusProvider

            redis_cfg = config["redis"]
            event_bus_provider = RedisEventBusProvider(
                host=redis_cfg["host"],
                port=redis_cfg.get("port", 6379),
                password=redis_cfg.get("password", ""),
                db=redis_cfg.get("db", 0),
            )
        case _:
            raise ValueError(
                "Unsupported event bus provider type: "
                f"{config['provider']['event_bus']}"
            )

    ProviderManager().register(event_bus_provider)

    if "scheduling" in get_enabled_extensions(config):
        match config["provider"].get("scheduling", "local"):
            case "local":
                from include.providers.scheduling import LocalSchedulingProvider

                scheduling_provider = LocalSchedulingProvider(
                    SchedulingPolicy.from_config(config)
                )
            case "redis":
                from include.providers.scheduling.redis import RedisSchedulingProvider

                scheduling_provider = RedisSchedulingProvider.from_config(config)
            case _:
                raise ValueError(
                    "Unsupported scheduling provider type: "
                    f"{config['provider']['scheduling']}"
                )
        ProviderManager().register(scheduling_provider)
