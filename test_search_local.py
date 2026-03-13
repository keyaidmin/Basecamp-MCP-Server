#!/usr/bin/env python3
"""Run Basecamp search locally for debugging. Load .env, call official search API, print results."""
import os
import sys
import json

# Ensure we load .env from this directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dotenv import load_dotenv
load_dotenv()

from basecamp_client import BasecampClient
from search_utils import BasecampSearch

def main():
    query = sys.argv[1] if len(sys.argv) > 1 else "CV recognition"
    account_id = os.getenv("BASECAMP_ACCOUNT_ID")
    if not account_id:
        print("Set BASECAMP_ACCOUNT_ID in .env (and run OAuth to get tokens in oauth_tokens.json)")
        sys.exit(1)
    from token_storage import get_token
    token = get_token()
    if not token or not token.get("access_token"):
        print("No OAuth token. Run oauth_app.py and complete login at http://localhost:8000")
        sys.exit(1)
    client = BasecampClient(
        access_token=token["access_token"],
        account_id=account_id,
        user_agent=os.getenv("USER_AGENT", "Basecamp MCP Test"),
        auth_mode="oauth",
    )
    search = BasecampSearch(client=client)
    print(f"Query: {query!r}")
    print("--- Official API (search_recordings_api) ---")
    try:
        recordings = search.search_recordings_api(query, per_page=20)
        print(json.dumps(recordings, indent=2, default=str)[:4000])
        if isinstance(recordings, list):
            print(f"\nCount: {len(recordings)}")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
