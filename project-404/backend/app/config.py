from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql://scanner:scanner@postgres:5432/scanner"
    redis_url: str = "redis://redis:6379/0"
    secret_key: str = "change-me-in-production-32-chars!!"
    user_agent: str = "OutsideInScanner/1.0 (security-research)"
    max_response_size: int = 2 * 1024 * 1024  # 2 MB
    crawl_timeout: float = 10.0
    crawl_max_depth: int = 2
    crawl_concurrency: int = 5
    max_requests_per_scan: int = 400
    max_discovered_endpoints: int = 2000
    brute_force_wordlist_limit: int = 80
    max_hosts_to_probe: int = 50
    probe_timeout: float = 10.0
    rate_limit_delay: float = 0.3
    log_level: str = "INFO"

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()
