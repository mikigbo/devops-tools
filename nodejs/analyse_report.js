const fs = require('fs');

function processVulnerabilityReport(reportFile, whitelist) {
    const reportData = JSON.parse(fs.readFileSync(reportFile, 'utf8'));

    let totalVulnerabilities = 0;
    let vulnerabilities = [];
    const severityCounts = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };

    reportData.Results.forEach(result => {
        console.log(JSON.stringify(result.Vulnerabilities, null, 2));
        vulnerabilities = vulnerabilities.concat(result.Vulnerabilities || []);
    });


   // console.log(JSON.stringify(vulnerabilities, null, 2));

    totalVulnerabilities = vulnerabilities.length;
    let whitelistedCount = 0;

    vulnerabilities.forEach(vuln => {
        const vulnId = vuln.VulnerabilityID || '';
        const severity = vuln.Severity || '';

        if (severity in severityCounts) {
            severityCounts[severity]++;
        }

        console.log(`Processing vulnerability: ${vulnId} (Severity: ${severity})`);

        if (whitelist[vulnId] === severity) {
            whitelistedCount++;
        }
    });

    console.log('Severity Counts:');
    for (const [level, count] of Object.entries(severityCounts)) {
        console.log(`${level}: ${count}`);
    }

    if (whitelistedCount === totalVulnerabilities) {
        console.log('Vulnerability check passed. All vulnerabilities are whitelisted.');
        return true;
    } else {
        console.log('Vulnerability check failed. Non-whitelisted vulnerabilities found.');
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
