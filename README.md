# AI-Based Phishing & Scam Detection System

## Project Overview

The AI-Based Phishing & Scam Detection System is a Python-based cybersecurity application designed to help users identify potentially malicious URLs, phishing emails and scam SMS messages.

The application combines external threat-intelligence services, rule-based risk analysis and generative AI to help users understand potential online threats. It also includes an AI-powered cybersecurity chatbot and an interactive dashboard for viewing scan statistics and previous scan records.

This project was developed using an existing GitHub project as an initial reference. The implementation was subsequently rewritten, modified, customized and extended through independent development, including frontend and backend development, database integration, API integration and application functionality.

## Features

### 1. URL Phishing Detection
- Allows users to submit URLs for security analysis.
- Integrates the VirusTotal API to retrieve URL threat information.
- Calculates a risk score based on available threat signals.
- Classifies URLs as Safe, Suspicious or Malicious.
- Supports optional URL submission to URLScan.io for additional analysis.

### 2. Email Scam Detection
- Allows users to enter suspicious email content.
- Identifies suspicious keywords and common scam indicators.
- Calculates a risk score using predefined detection rules.
- Displays the analysis result and detected warning signals.

### 3. SMS Scam Detection
- Analyzes SMS messages for common scam indicators.
- Uses keyword-based risk analysis.
- Generates a risk score and displays the detection result.

### 4. AI-Powered Explanations
- Integrates the Groq API with LangChain.
- Generates understandable explanations of scan results.
- Provides explanations in Nepali.
- Includes fallback explanations when the AI service is unavailable.

### 5. Cybersecurity Awareness Chatbot
- Provides an interactive chatbot for cybersecurity-related questions.
- Uses Groq and LangChain for AI-generated responses.
- Helps users understand phishing, online scams, password safety and secure browsing practices.

### 6. Interactive Dashboard
- Displays total URL, email and SMS scans.
- Provides a breakdown of risk classifications.
- Displays recent scan history.
- Retrieves stored scan information from the MySQL database.

## Technologies Used

| Category | Technologies |
|---|---|
| Programming Language | Python |
| Frontend | Streamlit |
| Backend | FastAPI |
| Database | MySQL |
| ORM | SQLAlchemy |
| Database Driver | PyMySQL |
| AI Integration | Groq API, LangChain |
| Threat Intelligence | VirusTotal API, URLScan.io API |
| HTTP Requests | Requests |
| Configuration | Python dotenv |
| Version Control | Git, GitHub |
| Development Environment | Visual Studio Code |

## System Architecture

The application follows a frontend-backend architecture.

1. Users interact with the application through the Streamlit frontend.
2. The frontend communicates with the FastAPI backend through HTTP requests.
3. The backend processes URL, email and SMS scan requests.
4. URL scans retrieve threat information using VirusTotal, while email and SMS scans use predefined keyword-based risk analysis.
5. Groq and LangChain generate explanations and chatbot responses when configured.
6. Scan records and relevant application data are stored in the MySQL database.
7. The dashboard retrieves statistics and scan history through backend API endpoints.

## Risk Classification

The application uses a risk-scoring mechanism to classify suspicious content.

| Risk Score | Classification |
|---|---|
| 0–24 | Safe |
| 25–59 | Suspicious |
| 60–100 | Malicious |

The risk classification is based on configured scoring rules and available threat-intelligence signals. The results are intended as security indicators and should not be treated as a guarantee that a URL or message is completely safe.

## Project Structure

```text
Phishing_Scam_Detection/
│
├── backend/
│   ├── main.py
│   ├── database.py
│   └── requirements.txt
│
├── frontend/
│   ├── app.py
│   └── requirements.txt
│
├── .gitignore
└── README.md
```

## Installation and Setup

### Prerequisites

- Python 3.11 or later
- MySQL Server
- Git
- VirusTotal API key
- Groq API key
- URLScan.io API key (optional)

### Step 1: Clone the Repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd Phishing_Scam_Detection
```

### Step 2: Create the MySQL Database

Open MySQL and execute:

```sql
CREATE DATABASE phishing_detection;
```

The application creates its required tables when the backend initializes.

### Step 3: Set Up the Backend

Navigate to the backend directory:

```bash
cd backend
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate it on Windows:

```powershell
venv\Scripts\Activate.ps1
```

Install the required dependencies:

```bash
pip install -r requirements.txt
```

Create a `.env` file inside the backend directory:

```env
DATABASE_URL=mysql+pymysql://root:YOUR_PASSWORD@localhost:3306/phishing_detection
VIRUSTOTAL_API_KEY=your_virustotal_api_key
URLSCAN_API_KEY=your_urlscan_api_key
GROQ_API_KEY=your_groq_api_key
```

Replace the example values with your actual configuration. Never upload API keys or database passwords to GitHub.

### Step 4: Set Up the Frontend

Open another terminal in the main project directory:

```bash
cd frontend
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate it:

```powershell
venv\Scripts\Activate.ps1
```

Install frontend dependencies:

```bash
pip install -r requirements.txt
```

Create a `.env` file inside the frontend directory:

```env
BACKEND_URL=http://localhost:8000
```

### Step 5: Run the Backend

From the backend directory, activate the virtual environment and execute:

```bash
uvicorn main:app --reload
```

The backend will run at:

```text
http://localhost:8000
```

FastAPI interactive API documentation:

```text
http://localhost:8000/docs
```

### Step 6: Run the Frontend

Open another terminal, navigate to the frontend directory, activate its virtual environment and execute:

```bash
streamlit run app.py
```

The application will be available at:

```text
http://localhost:8501
```

## API Endpoints

| HTTP Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Checks backend availability |
| POST | `/api/url/scan` | Scans submitted URLs |
| POST | `/api/email/scan` | Analyzes email content |
| POST | `/api/sms/scan` | Analyzes SMS messages |
| POST | `/api/chatbot/ask` | Processes cybersecurity chatbot questions |
| GET | `/api/dashboard/stats` | Retrieves dashboard statistics |
| GET | `/api/dashboard/history` | Retrieves recent scan history |

## Learning Outcomes

Working on this project provided practical experience in:

- Developing Python-based applications.
- Building REST APIs using FastAPI.
- Creating interactive web interfaces using Streamlit.
- Integrating MySQL databases using SQLAlchemy.
- Connecting applications with external threat-intelligence APIs.
- Implementing rule-based risk-scoring mechanisms.
- Integrating generative AI using Groq and LangChain.
- Managing API credentials and environment variables.
- Understanding frontend-backend communication.
- Using Git and GitHub for project version control.

## Limitations

- Email and SMS detection currently use predefined keyword-based rules rather than a trained machine learning classifier.
- URL analysis depends on the threat information returned by external services.
- URLScan.io submission is optional and does not directly determine the displayed URL risk score.
- AI explanations and chatbot responses require a valid Groq API key.
- External API usage may be subject to rate limits and service availability.
- Risk classifications are indicators and cannot guarantee complete protection against online threats.

## Future Enhancements

- Implement machine learning models for phishing email and SMS classification.
- Improve URL analysis using multiple threat-intelligence sources.
- Introduce user authentication and personalized scan history.
- Add downloadable security analysis reports.
- Enhance dashboard analytics and visualizations.
- Expand cybersecurity awareness and educational resources.

## Developer

**Sayli Krishnadev Shelar**

M.Sc. Artificial Intelligence Student | B.Sc. Information Technology Graduate

- GitHub: https://github.com/sayli-11
- LinkedIn: https://www.linkedin.com/in/saylishelar

## Project Acknowledgement

This project was developed using an existing GitHub implementation as a starting reference. The codebase was subsequently modified, rewritten and extended as part of independent development and academic learning.

Original source and licence information should be retained in accordance with the original repository's licence and attribution requirements.

---

*This project is intended for educational and cybersecurity awareness purposes. It is not a substitute for professional cybersecurity tools or independent security verification.*