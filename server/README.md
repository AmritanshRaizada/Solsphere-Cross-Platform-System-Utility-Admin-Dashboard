# FastAPI Backend

This is a minimal FastAPI backend with SQLite database integration.

## Setup

1.  **Create a virtual environment** (optional but recommended):
    ```bash
    python -m venv venv
    source venv/bin/activate
    ```

2.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Configure environment variables**:
    Create a `.env` file in the `server` directory with the following content:
    ```
    DATABASE_URL="sqlite:///./test.db"
    API_TOKEN="your_secret_api_token"
    ```
    *   `DATABASE_URL`: Path to your SQLite database file.
    *   `API_TOKEN`: A secret token for API authentication (not implemented in this minimal example, but good practice to include).

## Running the Application

To run the FastAPI application, navigate to the `server` directory and execute:

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 4000
```

**Important Notes:**
*   Ensure your `.env` file contains `BEARER_TOKEN` and `DB_PATH` for proper application functionality.
*   CORS is configured to allow all origins for simplicity in this example.

The API will be accessible at `http://0.0.0.0:4000`.
The API documentation (Swagger UI) will be available at `http://0.0.0.0:4000/docs`.

## API Endpoints

*   **GET /**: Welcome message.
*   **POST /items/**: Create a new item.
*   **GET /items/**: Retrieve all items.
*   **GET /items/{item_id}**: Retrieve a single item by ID.
*   **PUT /items/{item_id}**: Update an existing item.
*   **DELETE /items/{item_id}**: Delete an item.
