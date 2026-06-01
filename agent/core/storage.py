import os
from dotenv import load_dotenv
load_dotenv()

def get_storage_client():
    try:
        from google.cloud import storage
        return storage.Client(
            project=os.getenv("GOOGLE_CLOUD_PROJECT")
        )
    except Exception as e:
        print(f"[Storage] GCS unavailable: {e}")
        return None

def save_report(investigation_id: str, content: str) -> str:
    """Save executive report to GCS. Returns public URL or local path."""
    bucket_name = os.getenv("GCS_BUCKET", "")
    
    # Save locally always
    os.makedirs("reports/executive", exist_ok=True)
    local_path = f"reports/executive/{investigation_id}.txt"
    with open(local_path, "w") as f:
        f.write(content)
    
    # Try GCS if bucket configured
    if bucket_name:
        try:
            client = get_storage_client()
            if client:
                bucket = client.bucket(bucket_name)
                blob = bucket.blob(
                    f"reports/{investigation_id}.txt"
                )
                blob.upload_from_string(content)
                print(f"[Storage] Report saved to GCS: "
                      f"gs://{bucket_name}/reports/{investigation_id}.txt")
                return f"gs://{bucket_name}/reports/{investigation_id}.txt"
        except Exception as e:
            print(f"[Storage] GCS upload failed: {e}")
    
    print(f"[Storage] Report saved locally: {local_path}")
    return local_path

def save_playbook(filename: str, content: dict) -> str:
    """Save playbook to GCS. Returns path."""
    import json
    bucket_name = os.getenv("GCS_BUCKET", "")
    
    # Save locally always
    os.makedirs("playbooks", exist_ok=True)
    local_path = f"playbooks/{filename}"
    with open(local_path, "w") as f:
        json.dump(content, f, indent=2)
    
    # Try GCS if bucket configured
    if bucket_name:
        try:
            client = get_storage_client()
            if client:
                bucket = client.bucket(bucket_name)
                blob = bucket.blob(f"playbooks/{filename}")
                blob.upload_from_string(
                    json.dumps(content, indent=2)
                )
                print(f"[Storage] Playbook saved to GCS: "
                      f"gs://{bucket_name}/playbooks/{filename}")
                return f"gs://{bucket_name}/playbooks/{filename}"
        except Exception as e:
            print(f"[Storage] GCS upload failed: {e}")
    
    print(f"[Storage] Playbook saved locally: {local_path}")
    return local_path

def load_playbooks_from_gcs():
    """Download latest playbooks from GCS on startup."""
    import json, glob
    bucket_name = os.getenv("GCS_BUCKET", "")
    if not bucket_name:
        return
    try:
        client = get_storage_client()
        if not client:
            return
        bucket = client.bucket(bucket_name)
        blobs = bucket.list_blobs(prefix="playbooks/")
        os.makedirs("playbooks", exist_ok=True)
        for blob in blobs:
            filename = blob.name.split("/")[-1]
            if filename.endswith(".json"):
                content = blob.download_as_text()
                with open(f"playbooks/{filename}", "w") as f:
                    f.write(content)
                print(f"[Storage] Loaded from GCS: {filename}")
    except Exception as e:
        print(f"[Storage] Could not load from GCS: {e}")
