const fs = require('fs');

function processVulnerabilityReport(reportFile, whitelist) {
    const reportData = JSON.parse(fs.readFileSync(reportFile, 'utf8'));

    let vulnerabilities = [];
    const severityCounts = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };

    reportData.Results.forEach(result => {
        vulnerabilities = vulnerabilities.concat(result.Vulnerabilities || []);
    });

    const totalVulnerabilities = vulnerabilities.length;
    let whitelistedCount = 0;

    vulnerabilities.forEach(vuln => {
        const vulnId = vuln.VulnerabilityID || '';
        const severity = vuln.Severity || '';

        if (severity in severityCounts) {
            severityCounts[severity]++;
        }

        if (whitelist[vulnId] === severity) {
            whitelistedCount++;
        }
    });

    console.log('Severity Counts:');
    for (const [level, count] of Object.entries(severityCounts)) {
        console.log(`${level}: ${count}`);
    }

    // Check if there are no critical or high vulnerabilities
    if (severityCounts['CRITICAL'] === 0 && severityCounts['HIGH'] === 0) {
        console.log('No critical or high vulnerabilities found. Vulnerability check passed.');
        return true;
    } else {
        console.log('Critical or high vulnerabilities found. Vulnerability check failed.');
        return false;
    }
}

if (process.argv.length < 3) {
    console.log('Usage: node script.js path/to/report.json');
    process.exit(1);
}

const reportFile = process.argv[2];

// Example whitelist of vulnerabilities to exempt
const whitelist = {
    'CVE-2021-1234': 'LOW',
    'CVE-2022-5678': 'MEDIUM',
};

if (processVulnerabilityReport(reportFile, whitelist)) {
    process.exit(0); // Success exit code
} else {
    process.exit(1); // Failure exit code
}
