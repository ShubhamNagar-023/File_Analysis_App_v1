# API Documentation

Production-grade REST API for file analysis.

## Quick Start

### Start API Server

```bash
# Default (localhost:5000)
python api_server.py

# Custom port
python api_server.py --port 8080

# Custom host (for network access)
python api_server.py --host 0.0.0.0 --port 5000
```

### Using with Frontend

```bash
# Start integrated (API + UI)
python start.py

# Start API only
python start.py --api --port 5000
```

## API Endpoints

### Health Check

```http
GET /api/health
```

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2026-01-05T21:30:00.000000"
}
```

### Analyze File

```http
POST /api/analyze
Content-Type: multipart/form-data

file: <binary>
case_name: "Investigation XYZ" (optional)
session_name: "Analysis Session" (optional)
```

**Response:**
```json
{
  "success": true,
  "record_id": "REC-ABC123DEF456",
  "case_id": "CASE-12345678",
  "session_id": "SES-87654321",
  "results": {
    "file_name": "suspicious.exe",
    "file_size": 524288,
    "semantic_file_type": "PE_EXECUTABLE",
    "risk_score": 75.5,
    "severity": "HIGH",
    "sha256_hash": "abcd1234...",
    "created_at": "2026-01-05T21:30:00"
  },
  "exports": {
    "json": "/path/to/suspicious_analysis.json",
    "html": "/path/to/suspicious_analysis.html",
    "pdf": "/path/to/suspicious_analysis.pdf"
  }
}
```

### List Records

```http
GET /api/records
```

**Response:**
```json
{
  "success": true,
  "count": 15,
  "records": [
    {
      "record_id": "REC-123...",
      "file_name": "suspicious.exe",
      "risk_score": 75.5,
      "severity": "HIGH",
      ...
    }
  ]
}
```

### Get Specific Record

```http
GET /api/records/{record_id}
```

**Response:**
```json
{
  "success": true,
  "record": {
    "record_id": "REC-123...",
    "file_name": "suspicious.exe",
    "part1": { /* complete PART 1 results */ },
    "part2": { /* complete PART 2 results */ },
    "part3": { /* complete PART 3 results */ }
  }
}
```

### Export Record

```http
GET /api/records/{record_id}/export/{format}
```

**Formats:** `json`, `html`, `pdf`

**Response:** File download

### List Cases

```http
GET /api/cases
```

**Response:**
```json
{
  "success": true,
  "count": 5,
  "cases": [
    {
      "case_id": "CASE-123...",
      "name": "Investigation XYZ",
      "created_at": "2026-01-05T21:00:00"
    }
  ]
}
```

### Get Statistics

```http
GET /api/stats
```

**Response:**
```json
{
  "success": true,
  "statistics": {
    "total_cases": 5,
    "total_sessions": 12,
    "total_records": 48,
    "severity_distribution": {
      "INFORMATIONAL": 20,
      "LOW": 15,
      "MEDIUM": 8,
      "HIGH": 4,
      "CRITICAL": 1
    }
  }
}
```

## Usage Examples

### Python

```python
import requests

# Analyze a file
with open('suspicious.exe', 'rb') as f:
    files = {'file': f}
    data = {'case_name': 'Investigation 2026-01'}
    response = requests.post('http://localhost:5000/api/analyze', 
                           files=files, data=data)
    result = response.json()
    print(f"Risk Score: {result['results']['risk_score']}")
    print(f"Severity: {result['results']['severity']}")

# List all records
response = requests.get('http://localhost:5000/api/records')
records = response.json()['records']
for record in records:
    print(f"{record['file_name']}: {record['severity']}")
```

### curl

```bash
# Analyze a file
curl -X POST http://localhost:5000/api/analyze \
  -F "file=@suspicious.exe" \
  -F "case_name=Investigation 2026-01"

# Get health status
curl http://localhost:5000/api/health

# List records
curl http://localhost:5000/api/records

# Export as PDF
curl http://localhost:5000/api/records/REC-ABC123/export/pdf \
  -o report.pdf
```

### JavaScript (Frontend)

```javascript
// Analyze a file
const formData = new FormData();
formData.append('file', fileInput.files[0]);
formData.append('case_name', 'Investigation 2026-01');

const response = await fetch('http://localhost:5000/api/analyze', {
    method: 'POST',
    body: formData
});

const result = await response.json();
console.log('Risk Score:', result.results.risk_score);
console.log('Severity:', result.results.severity);
```

## Production Deployment

### Standalone API Server

```bash
# Install dependencies
pip install -r requirements.txt

# Start server (production)
python api_server.py --host 0.0.0.0 --port 8080
```

### With Nginx Reverse Proxy

```nginx
server {
    listen 80;
    server_name fileanalysis.example.com;

    location /api/ {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Docker Deployment

```dockerfile
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 5000
CMD ["python", "api_server.py", "--host", "0.0.0.0", "--port", "5000"]
```

## Security Considerations

**For Production:**

1. **Authentication** - Add API keys or OAuth
2. **Rate Limiting** - Prevent abuse
3. **File Size Limits** - Prevent DoS
4. **HTTPS** - Use TLS in production
5. **CORS** - Configure allowed origins
6. **Input Validation** - Sanitize all inputs

## Error Handling

All endpoints return errors in this format:

```json
{
  "error": "Error message description"
}
```

HTTP Status Codes:
- `200` - Success
- `400` - Bad Request (invalid input)
- `404` - Not Found
- `500` - Internal Server Error
