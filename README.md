# Endpoint Security and Monitoring Tools
Security tool for monitoring endpoints

## Overview
This project is a security tool designed for endpoint monitoring.  
It provides various security monitoring capabilities to observe and track activities on endpoint devices.

## Features
**Planned to add in the future**
- **USB File Transfer Monitoring**: Tracking of file transfers to USB devices

## System Architecture
```mermaid
sequenceDiagram
    box User Environment
        participant User as PC
        participant Tools as Endpoint Tools
    end

    box AWS
        participant API as Data Collector Database(Lambda Function)
        participant DB as Database
        participant Dashboard as Admin Dashboard(Amplify)
    end

    box Admin Environment
        participant Admin as PC 
    end

    rect rgb(240, 240, 240)
        Note over Tools,User: Monitor
            Tools->>User: Monitoring
            User-->>Tools: Event Data
    end
    
    rect rgb(240, 240, 240)
        Note over Tools,DB: Data Transmission
            Tools->>API: Send Event Data
            API->>DB: Store Event Data
            API-->>Tools: Confirmation
    end

    rect rgb(240, 240, 240)
        Note over DB,Admin: Admin Operations
            Admin->>Dashboard: Login
            Dashboard->>DB: Query Events
            DB-->>Dashboard: Return Event Data
            Dashboard-->>Admin: Show Event Data 
    end
    
    rect rgb(240, 240, 240)
        Note over User,Admin: Alert Scenario
            alt Suspicious Activity Detected
                Admin->>Dashboard: Show Event Data
                Admin->>User: Implement Security Measure
            end
    end
```

## Technology Stack
- Endpoint Tools
    - Go Lang
- Data Collector Database
    - AWS
        - Lambda
            - Python
- Database
    - AWS
        - DynamoDB
- Admin Dashboard
    - AWS
        - Amplify
    - React
