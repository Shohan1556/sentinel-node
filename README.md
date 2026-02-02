# SentinelNode: Secure Centralized Logging & Audit


A Python-based cybersecurity system for detecting SSH brute-force attacks through intelligent log analysis and multi-channel alerting.

## 🚀 Features

- **Real-time SSH Brute-Force Detection**: Analyzes authentication logs to identify attack patterns
- **Multi-Channel Alerting**: 
  - Console output for immediate visibility
  - CSV logging for historical analysis
  - PostgreSQL database persistence for centralized storage
- **Configurable Thresholds**: Customize detection sensitivity
- **Secure Database Integration**: SSL-enabled connection to Neon PostgreSQL
- **Graceful Fallback**: Continues operation even if database is unavailable
- **Production-Ready**: Comprehensive error handling and logging

## 📋 Requirements

- Python 3.8+
- PostgreSQL database (Neon DB recommended)
- SSH authentication logs (auth.log format)

## 🔧 Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Shohan1556/sentinel-node.git
   cd sentinel-node
   ```

2. **Create and activate virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## ⚙️ Configuration

### Database Setup (Optional)

Database persistence is **optional**. The system works perfectly with console and CSV output only.

1. **Copy the environment template**:
   ```bash
   cp .env.example .env
   ```

2. **Edit `.env` with your database credentials**:
   ```env
   DB_HOST=your-database-host.aws.neon.tech
   DB_PORT=5432
   DB_NAME=your-database-name
   DB_USER=your-database-user
   DB_PASSWORD=your-database-password
   DB_SSL_MODE=require
   ```

3. **For Neon DB** (recommended):
   - Sign up at [neon.tech](https://neon.tech)
   - Create a new project
   - Copy connection details to `.env`

### Application Settings

Edit `src/config.py` to customize:
- `log_path`: Path to your auth.log file
- `threshold`: Number of failed attempts to trigger alert (default: 5)
- `alert_output`: CSV file path for alerts

## 🎯 Usage

### Basic Usage (Console + CSV)

```bash
python main.py
```

This will:
- Parse the configured auth.log file
- Detect brute-force patterns
- Print alerts to console
- Save alerts to CSV file

### With Database Persistence

1. **Configure database** (see Configuration section above)

2. **Test database connection**:
   ```bash
   python scripts/test_db_insert.py
   ```

3. **Run the system**:
   ```bash
   python main.py
   ```

Alerts will now be stored in:
- Console (stdout)
- CSV file (`data/processed/alerts.csv`)
- PostgreSQL database (`alerts` table)

### CICIDS2017 Dataset Detection
To detect SSH brute-force attacks in CICIDS2017 CSV data:

```bash
python main.py --mode csv --input data/raw/begin_monday_workinghour.pcap_ISCX.csv
```

**Note on Dataset**: The provided sample file `Benign-Monday-WorkingHours.pcap_ISCX.csv` contains only benign traffic. To validate detection, use a dataset containing SSH-BruteForce labels or use the provided test suite which generates synthetic attack data.

### Custom Log File

```bash
python main.py --mode log --input /path/to/custom/auth.log
```

## 🔬 Research Validation
This system reproduces the detection logic from **Khan & Rahman (2023)**:
- **Rule**: ≥5 connection attempts from same Source IP to port 22 within 2 minutes.
- **Method**: Sliding time-window analysis.
- **Validation**: Verified against CICIDS2017 data schema.

| Metric | Value | Notes |
|--------|-------|-------|
| Detection Window | 2 minutes | Sliding window implementation |
| Threshold | 5 attempts | Configurable via code |
| Dataset | CICIDS2017 | Validated on standard pillars |

## 🗄️ Database Schema

The `alerts` table structure:

```sql
CREATE TABLE alerts (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    ip_address INET NOT NULL,
    event_type TEXT NOT NULL,
    status TEXT DEFAULT 'new',
    machine_ip INET,
    machine_name TEXT,
    browser TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);
```

**Indexes** for performance:
- `idx_alerts_timestamp` on `timestamp`
- `idx_alerts_ip_address` on `ip_address`
- `idx_alerts_status` on `status`

## 📊 Example Output

```
============================================================
SentinelNode: Secure Centralized Logging & Audit
============================================================
INFO - Sentinel Node starting...
INFO - Database configuration detected. Initializing connection...
INFO - Database connection pool created successfully
INFO - ✓ Database connection successful
INFO - AlertManager initialized:
INFO -   - Console output: Enabled
INFO -   - CSV output: Enabled
INFO -   - Database output: Enabled
INFO - Processing log file: data/raw/sample_auth.log

ALERT: [ALERT] Brute-force detected from 192.168.1.100 at 2026-01-28 15:30:45

============================================================
Analysis Complete: 1 brute-force attack(s) detected
============================================================

✓ Alerts saved to: data/processed/alerts.csv
✓ Alerts stored in database
```

## 🧪 Testing

### Test Database Connection

```bash
python scripts/test_db_insert.py
```

This script will:
1. Verify database configuration
2. Test connection
3. Insert a mock alert
4. Query and display recent alerts
5. Test status updates

### Run Unit Tests

```bash
pytest
```

### Run with Coverage

```bash
pytest --cov=src tests/
```

## 🔒 Security Best Practices

1. **Never commit `.env` file**: It contains sensitive credentials
2. **Use SSL mode**: Always set `DB_SSL_MODE=require` for production
3. **Rotate credentials**: Regularly update database passwords
4. **Restrict database access**: Use firewall rules and IP whitelisting
5. **Monitor logs**: Review application logs for suspicious activity

## 🛠️ Troubleshooting

### Database Connection Issues

**Problem**: `Failed to initialize database`

**Solutions**:
- Verify credentials in `.env` file
- Check network connectivity to database host
- Ensure SSL mode is set to `require`
- Verify database exists and user has permissions

**Fallback**: System continues with CSV output only

### No Alerts Detected

**Problem**: Log file processed but no alerts generated

**Solutions**:
- Verify log file format matches expected pattern
- Check threshold setting in `src/config.py`
- Ensure log file contains failed login attempts
- Review log file path configuration

### CSV File Errors

**Problem**: `Error writing to CSV`

**Solutions**:
- Ensure `data/processed/` directory exists
- Check file permissions
- Verify disk space availability

## 📁 Project Structure

```
sentinel-node/
├── src/
│   ├── __init__.py
│   ├── alert_manager.py      # Multi-channel alert distribution
│   ├── anomaly_detector.py   # Brute-force detection logic
│   ├── config.py              # Configuration management
│   ├── db_connector.py        # PostgreSQL database interface
│   └── log_parser.py          # Auth log parsing
├── scripts/
│   ├── test_db_insert.py      # Database testing utility
│   └── simulate_attack.py     # Attack simulation for testing
├── data/
│   ├── raw/                   # Input log files
│   └── processed/             # Output CSV files
├── tests/                     # Unit tests
├── main.py                    # Application entry point
├── requirements.txt           # Python dependencies
├── .env.example               # Environment variable template
└── README.md                  # This file
```

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Authors

- **Durjoy Acharya** - Initial work - [Shohan1556](https://github.com/Shohan1556)

## 🙏 Acknowledgments

- Neon Database for PostgreSQL hosting
- Python community for excellent libraries
- Cybersecurity community for threat intelligence

## 📞 Support

For issues and questions:
- Open an issue on GitHub
- Check existing documentation
- Review troubleshooting section

---

**Note**: This is a capstone project for educational purposes. Always follow your organization's security policies and legal requirements when deploying security monitoring tools.
