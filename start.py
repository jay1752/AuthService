import argparse
import os
import subprocess
import sys
import uvicorn


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the API server.")
    parser.add_argument(
        "--host", type=str, default="0.0.0.0", help="Host to bind the server to."
    )
    parser.add_argument(
        "--port", type=int, default=8000, help="Port to bind the server to."
    )
    parser.add_argument(
        "--reload", action="store_true", help="Enable auto-reload for development."
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Number of worker processes (gunicorn only).",
    )
    parser.add_argument(
        "--use-gunicorn",
        action="store_true",
        help="Use gunicorn instead of uvicorn for production.",
    )
    return parser.parse_args()


def run_uvicorn(host, port, reload):
    """Run the server using uvicorn."""
    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


def run_gunicorn(host, port, workers):
    """Run the server using gunicorn."""
    if workers is None:
        # Default to number of CPU cores
        workers = os.cpu_count() or 1
    
    bind = f"{host}:{port}"
    cmd = [
        "gunicorn",
        "app.main:app",
        "--bind", bind,
        "--workers", str(workers),
        "--worker-class", "uvicorn.workers.UvicornWorker",
        "--forwarded-allow-ips", "*",
        "--access-logfile", "-",
    ]
    
    subprocess.run(cmd)


if __name__ == "__main__":
    args = parse_args()
    
    if args.use_gunicorn:
        run_gunicorn(args.host, args.port, args.workers)
    else:
        run_uvicorn(args.host, args.port, args.reload) 