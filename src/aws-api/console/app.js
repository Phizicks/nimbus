// LocalCloud Console - Main Application JavaScript

const API_BASE = '/';

// Global state for S3 navigation
let currentBucket = '';
let currentPrefix = '';
let currentSecretName = null;

// S3 credentials - adjust these for your environment
const S3_CONFIG = {
    accessKeyId: 'localcloud',
    secretAccessKey: 'localcloud',
    region: 'ap-southeast-2',
    endpoint: 'http://localhost:4566'
};

// ============================================================================
// Theme Management
// ============================================================================

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}


function setCookie(name, value, days = 365) {
    const expires = new Date(Date.now() + days * 864e5).toUTCString();
    document.cookie = `${name}=${value}; expires=${expires}; path=/`;
}

function setTheme(theme) {
    // Save to cookie
    setCookie('theme', theme);

    // Apply theme
    const html = document.documentElement;
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

    if (theme === 'dark' || (theme === 'system' && prefersDark)) {
        html.setAttribute('data-theme', 'dark');
    } else if (theme === 'light') {
        html.setAttribute('data-theme', 'light');
    } else {
        // System mode - remove attribute to let CSS media query handle it
        html.removeAttribute('data-theme');
    }

    // Update UI
    updateThemeUI(theme);

    // Close dropdown
    document.getElementById('theme-dropdown').classList.remove('active');
}

function updateThemeUI(currentTheme) {
    // Update icon in toggle button
    const icon = document.getElementById('theme-icon');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

    if (currentTheme === 'system') {
        icon.textContent = prefersDark ? '🌙' : '☀️';
    } else if (currentTheme === 'dark') {
        icon.textContent = '🌙';
    } else {
        icon.textContent = '☀️';
    }

    // Update checkmarks
    document.querySelectorAll('.theme-check').forEach(check => {
        check.classList.remove('active');
    });

    document.getElementById(`${currentTheme}-check`).classList.add('active');
}

function toggleThemePicker() {
    const dropdown = document.getElementById('theme-dropdown');
    dropdown.classList.toggle('active');
}

// Close dropdown when clicking outside
document.addEventListener('click', function (event) {
    const themePicker = document.querySelector('.theme-picker');
    const dropdown = document.getElementById('theme-dropdown');

    if (dropdown && themePicker && !themePicker.contains(event.target)) {
        dropdown.classList.remove('active');
    }
});

// Listen for system theme changes
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function () {
    const currentTheme = getCookie('theme') || 'system';
    if (currentTheme === 'system') {
        setTheme('system');
    }
});

// ============================================================================
// Notification system
function showNotification(message, type = 'info') {
    const container = document.getElementById('notification-container') || createNotificationContainer();

    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <div class="notification-content">
            <span class="notification-icon">${type === 'success' ? '✓' : type === 'error' ? '✕' : 'ℹ'}</span>
            <span class="notification-message">${message}</span>
        </div>
        <button class="notification-close" onclick="this.parentElement.remove()">×</button>
    `;

    container.appendChild(notification);

    // Auto-remove after 5 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    }, 5000);
}

function createNotificationContainer() {
    const container = document.createElement('div');
    container.id = 'notification-container';
    container.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 10000;
        display: flex;
        flex-direction: column;
        gap: 10px;
    `;
    document.body.appendChild(container);
    return container;
}

function showConfirmModal(message, onConfirm) {
    const modal = document.createElement('div');
    modal.className = 'modal active';
    modal.innerHTML = `
        <div class="modal-content" style="max-width: 400px;">
            <h2>Confirm Action</h2>
            <p style="margin: 20px 0;">${message}</p>
            <div style="display: flex; gap: 10px; justify-content: flex-end;">
                <button class="btn btn-secondary" onclick="this.closest('.modal').remove()">Cancel</button>
                <button class="btn btn-danger" id="confirm-action-btn">Confirm</button>
            </div>
        </div>
    `;

    document.body.appendChild(modal);

    document.getElementById('confirm-action-btn').onclick = () => {
        modal.remove();
        onConfirm();
    };
}

// ============================================================================
// AWS SIGNATURE V4 HELPER (lightweight implementation)
// ============================================================================

async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hmacSha256(key, message) {
    const enc = new TextEncoder();
    const algorithm = { name: 'HMAC', hash: 'SHA-256' };
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        typeof key === 'string' ? enc.encode(key) : key,
        algorithm,
        false,
        ['sign']
    );
    const signature = await crypto.subtle.sign(algorithm.name, cryptoKey, enc.encode(message));
    return new Uint8Array(signature);
}

async function getSignatureKey(key, dateStamp, regionName, serviceName) {
    const kDate = await hmacSha256('AWS4' + key, dateStamp);
    const kRegion = await hmacSha256(kDate, regionName);
    const kService = await hmacSha256(kRegion, serviceName);
    const kSigning = await hmacSha256(kService, 'aws4_request');
    return kSigning;
}

async function signRequest(method, path, queryString = '', payload = '', headers = {}) {
    const now = new Date();
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
    const dateStamp = amzDate.slice(0, 8);

    const host = S3_CONFIG.endpoint.replace(/^https?:\/\//, '');
    const service = 's3';
    const region = S3_CONFIG.region;

    // Canonical headers
    const canonicalHeaders = `host:${host}\nx-amz-date:${amzDate}\n`;
    const signedHeaders = 'host;x-amz-date';

    // Payload hash
    const payloadHash = await sha256(payload);

    // Canonical request
    const canonicalRequest = [
        method,
        path,
        queryString,
        canonicalHeaders,
        signedHeaders,
        payloadHash
    ].join('\n');

    // String to sign
    const algorithm = 'AWS4-HMAC-SHA256';
    const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
    const canonicalRequestHash = await sha256(canonicalRequest);
    const stringToSign = [
        algorithm,
        amzDate,
        credentialScope,
        canonicalRequestHash
    ].join('\n');

    // Calculate signature
    const signingKey = await getSignatureKey(S3_CONFIG.secretAccessKey, dateStamp, region, service);
    const signatureBytes = await hmacSha256(signingKey, stringToSign);
    const signature = Array.from(signatureBytes).map(b => b.toString(16).padStart(2, '0')).join('');

    // Authorization header
    const authorizationHeader = `${algorithm} Credential=${S3_CONFIG.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    return {
        'Host': host,
        'X-Amz-Date': amzDate,
        'Authorization': authorizationHeader,
        ...headers
    };
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function switchService(service) {
    // Save to localStorage
    localStorage.setItem('activeTab', service);

    // Update UI
    document.querySelectorAll('.service-nav button').forEach(btn => {
        btn.classList.remove('active');
    });
    document.getElementById(`service-button-${service}`).classList.add('active');

    document.querySelectorAll('.service-panel').forEach(panel => {
        panel.classList.remove('active');
    });
    document.getElementById(`${service}-panel`).classList.add('active');

    // Load appropriate data
    if (service === 'sqs') loadQueues();
    else if (service === 'dynamodb') loadTables();
    else if (service === 'lambda') loadFunctions();
    else if (service === 'ssm') loadParameters();
    else if (service === 'cloudwatch') loadLogGroups();
    else if (service === 'ecr') loadRepositories();
    else if (service === 's3') loadBuckets();
    else if (service === 'secretsmanager') loadSecrets();
}

function closeModal(modalId) {
    document.getElementById(modalId).classList.remove('active');
}

function showModal(modalId) {
    document.getElementById(modalId).classList.add('active');
}

// ============================================================================
// DYNAMODB FUNCTIONS
// ============================================================================

let currentTableName = '';
let currentTableKeys = {};

async function loadTables() {
    const loading = document.getElementById('dynamodb-loading');
    const content = document.getElementById('dynamodb-content');
    const empty = document.getElementById('dynamodb-empty');

    loading.style.display = 'block';
    content.style.display = 'none';
    empty.style.display = 'none';

    try {
        const response = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.0',
                'X-Amz-Target': 'DynamoDB_20120810.ListTables'
            },
            body: JSON.stringify({})
        });

        const data = await response.json();
        const tableNames = data.TableNames || [];

        if (tableNames.length === 0) {
            loading.style.display = 'none';
            empty.style.display = 'block';
            updateDynamoDBStats(0);
            return;
        }

        const tbody = document.querySelector('#dynamodb-table tbody');
        tbody.innerHTML = '';

        for (const tableName of tableNames) {
            const detailsResponse = await fetch(API_BASE, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-amz-json-1.0',
                    'X-Amz-Target': 'DynamoDB_20120810.DescribeTable'
                },
                body: JSON.stringify({ TableName: tableName })
            });

            const tableData = await detailsResponse.json();
            const table = tableData.Table || {};

            const keySchema = table.KeySchema || [];
            const partitionKey = keySchema.find(k => k.KeyType === 'HASH');
            const sortKey = keySchema.find(k => k.KeyType === 'RANGE');

            const row = tbody.insertRow();
            row.innerHTML = `
                <td><strong>${tableName}</strong></td>
                <td><span class="badge ${table.TableStatus === 'ACTIVE' ? 'badge-success' : 'badge-info'}">${table.TableStatus || 'UNKNOWN'}</span></td>
                <td>${partitionKey ? partitionKey.AttributeName : 'N/A'}</td>
                <td>${sortKey ? sortKey.AttributeName : '-'}</td>
                <td>
                    <div class="action-buttons">
                        <button class="btn btn-secondary" onclick="viewTableDetails('${tableName}')">Details</button>
                        <button class="btn btn-primary" onclick="viewTableItems('${tableName}')">Items</button>
                        <button class="btn btn-secondary" onclick="showCreateGSIModal('${tableName}')">Add GSI</button>
                        <button class="btn btn-danger" onclick="deleteTable('${tableName}')">Delete</button>
                    </div>
                </td>
            `;
        }

        updateDynamoDBStats(tableNames.length);
        loading.style.display = 'none';
        content.style.display = 'block';

    } catch (error) {
        console.error('Error loading tables:', error);
        loading.innerHTML = '<p style="color: var(--danger);">Error loading tables</p>';
    }
}

function updateDynamoDBStats(tableCount) {
    const statsDiv = document.getElementById('dynamodb-stats');
    statsDiv.innerHTML = `
        <div class="stat-card">
            <div class="stat-label">Total Tables</div>
            <div class="stat-value">${tableCount}</div>
        </div>
    `;
}

function showCreateTableModal() {
    document.getElementById('table-name').value = '';
    document.getElementById('partition-key-name').value = '';
    document.getElementById('partition-key-type').value = 'S';
    document.getElementById('has-sort-key').checked = false;
    document.getElementById('sort-key-name').value = '';
    document.getElementById('sort-key-type').value = 'S';
    document.getElementById('billing-mode').value = 'PAY_PER_REQUEST';
    toggleSortKey();
    toggleBillingMode();
    showModal('create-table-modal');
}

function toggleSortKey() {
    const hasSortKey = document.getElementById('has-sort-key').checked;
    document.getElementById('sort-key-section').style.display = hasSortKey ? 'block' : 'none';
}

function toggleBillingMode() {
    const billingMode = document.getElementById('billing-mode').value;
    document.getElementById('provisioned-settings').style.display =
        billingMode === 'PROVISIONED' ? 'block' : 'none';
}

async function createTable(event) {
    event.preventDefault();

    const tableName = document.getElementById('table-name').value;
    const partitionKeyName = document.getElementById('partition-key-name').value;
    const partitionKeyType = document.getElementById('partition-key-type').value;
    const hasSortKey = document.getElementById('has-sort-key').checked;
    const billingMode = document.getElementById('billing-mode').value;

    const keySchema = [{
        AttributeName: partitionKeyName,
        KeyType: 'HASH'
    }];

    const attributeDefinitions = [{
        AttributeName: partitionKeyName,
        AttributeType: partitionKeyType
    }];

    if (hasSortKey) {
        const sortKeyName = document.getElementById('sort-key-name').value;
        const sortKeyType = document.getElementById('sort-key-type').value;

        if (sortKeyName) {
            keySchema.push({
                AttributeName: sortKeyName,
                KeyType: 'RANGE'
            });

            attributeDefinitions.push({
                AttributeName: sortKeyName,
                AttributeType: sortKeyType
            });
        }
    }

    const requestBody = {
        TableName: tableName,
        KeySchema: keySchema,
        AttributeDefinitions: attributeDefinitions,
        BillingMode: billingMode
    };

    if (billingMode === 'PROVISIONED') {
        requestBody.ProvisionedThroughput = {
            ReadCapacityUnits: parseInt(document.getElementById('read-capacity').value),
            WriteCapacityUnits: parseInt(document.getElementById('write-capacity').value)
        };
    }

    try {
        await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.0',
                'X-Amz-Target': 'DynamoDB_20120810.CreateTable'
            },
            body: JSON.stringify(requestBody)
        });

        closeModal('create-table-modal');
        showNotification(`Table ${tableName} created successfully`, 'success');
        loadTables();
    } catch (error) {
        console.error('Error creating table:', error);
        showNotification('Error creating table', 'error');
    }
}

async function viewTableDetails(tableName) {
    try {
        const response = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.0',
                'X-Amz-Target': 'DynamoDB_20120810.DescribeTable'
            },
            body: JSON.stringify({ TableName: tableName })
        });

        const data = await response.json();
        const table = data.Table || {};

        document.getElementById('table-details-name').textContent = tableName;
        const content = document.getElementById('table-details-content');

        const keySchema = table.KeySchema || [];
        const partitionKey = keySchema.find(k => k.KeyType === 'HASH');
        const sortKey = keySchema.find(k => k.KeyType === 'RANGE');

        let html = `
            <div class="detail-row">
                <div class="detail-label">Table Name</div>
                <div class="detail-value">${table.TableName}</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Table ARN</div>
                <div class="detail-value"><code>${table.TableArn || 'N/A'}</code></div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Status</div>
                <div class="detail-value"><span class="badge ${table.TableStatus === 'ACTIVE' ? 'badge-success' : 'badge-info'}">${table.TableStatus}</span></div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Partition Key</div>
                <div class="detail-value">${partitionKey ? partitionKey.AttributeName : 'N/A'}</div>
            </div>
        `;

        if (sortKey) {
            html += `
                <div class="detail-row">
                    <div class="detail-label">Sort Key</div>
                    <div class="detail-value">${sortKey.AttributeName}</div>
                </div>
            `;
        }

        html += `
            <div class="detail-row">
                <div class="detail-label">Item Count</div>
                <div class="detail-value">${table.ItemCount || 0}</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Table Size</div>
                <div class="detail-value">${((table.TableSizeBytes || 0) / 1024).toFixed(2)} KB</div>
            </div>
        `;

        if (table.BillingModeSummary) {
            html += `
                <div class="detail-row">
                    <div class="detail-label">Billing Mode</div>
                    <div class="detail-value">${table.BillingModeSummary.BillingMode}</div>
                </div>
            `;
        }

        if (table.StreamSpecification) {
            html += `
                <div class="detail-row">
                    <div class="detail-label">StreamEnabled</div>
                    <div class="detail-value"><span class="badge ${table.StreamSpecification.StreamEnabled === true ? 'badge-success' : 'badge-info'}">${table.StreamSpecification.StreamEnabled}</span></div>
                    <div class="detail-label">StreamViewType</div>
                    <div class="detail-value">${table.StreamSpecification.StreamViewType}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">LatestStreamArn</div>
                    <div class="detail-value">${table.LatestStreamArn}</div>
                </div>
            `;
        }

        if (table.GlobalSecondaryIndexes && table.GlobalSecondaryIndexes.length > 0) {
            html += `
                <div class="detail-row">
                    <div class="detail-label">Global Secondary Indexes</div>
                    <div class="detail-value">
                        <table style="width: 100%; margin-top: 10px;">
                            <thead>
                                <tr>
                                    <th>Index Name</th>
                                    <th>Status</th>
                                    <th>Partition Key</th>
                                    <th>Sort Key</th>
                                </tr>
                            </thead>
                            <tbody>
            `;

            for (const gsi of table.GlobalSecondaryIndexes) {
                const gsiPartition = gsi.KeySchema.find(k => k.KeyType === 'HASH');
                const gsiSort = gsi.KeySchema.find(k => k.KeyType === 'RANGE');

                html += `
                    <tr>
                        <td>${gsi.IndexName}</td>
                        <td><span class="badge ${gsi.IndexStatus === 'ACTIVE' ? 'badge-success' : 'badge-info'}">${gsi.IndexStatus}</span></td>
                        <td>${gsiPartition ? gsiPartition.AttributeName : '-'}</td>
                        <td>${gsiSort ? gsiSort.AttributeName : '-'}</td>
                    </tr>
                `;
            }

            html += `
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        }

        content.innerHTML = html;
        showModal('table-details-modal');

    } catch (error) {
        console.error('Error loading table details:', error);
        showNotification('Error loading table details', 'error');
    }
}

async function viewTableItems(tableName) {
    currentTableName = tableName;

    try {
        const response = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.0',
                'X-Amz-Target': 'DynamoDB_20120810.DescribeTable'
            },
            body: JSON.stringify({ TableName: tableName })
        });

        const data = await response.json();
        const table = data.Table || {};

        currentTableKeys = {
            partition: table.KeySchema.find(k => k.KeyType === 'HASH')?.AttributeName,
            sort: table.KeySchema.find(k => k.KeyType === 'RANGE')?.AttributeName,
            attributes: table.AttributeDefinitions || []
        };

        document.getElementById('table-items-name').textContent = tableName;
        showModal('table-items-modal');
        loadTableItems();

    } catch (error) {
        console.error('Error loading table schema:', error);
        showNotification('Error loading table schema', 'error');
    }
}

async function loadTableItems() {
    const content = document.getElementById('table-items-content');
    content.innerHTML = '<div class="loading"><div class="spinner"></div><div>Loading items...</div></div>';

    try {
        const response = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.0',
                'X-Amz-Target': 'DynamoDB_20120810.Scan'
            },
            body: JSON.stringify({
                TableName: currentTableName,
                Limit: 25
            })
        });

        const data = await response.json();
        const items = data.Items || [];

        if (items.length === 0) {
            content.innerHTML = '<p>No items found in table</p>';
            return;
        }

        let html = `<div style="overflow-x: auto;"><table style="width: 100%;"><thead><tr>`;

        const allAttributes = new Set();
        items.forEach(item => {
            Object.keys(item).forEach(key => allAttributes.add(key));
        });

        allAttributes.forEach(attr => {
            html += `<th>${attr}</th>`;
        });
        html += `<th>Actions</th></tr></thead><tbody>`;

        items.forEach((item) => {
            html += '<tr>';
            allAttributes.forEach(attr => {
                const value = item[attr];
                let displayValue = 'N/A';

                if (value) {
                    if (value.S !== undefined) displayValue = value.S;
                    else if (value.N !== undefined) displayValue = value.N;
                    else if (value.BOOL !== undefined) displayValue = value.BOOL.toString();
                    else if (value.NULL !== undefined) displayValue = 'NULL';
                    else if (value.M !== undefined) displayValue = JSON.stringify(value.M);
                    else if (value.L !== undefined) displayValue = JSON.stringify(value.L);
                    else displayValue = JSON.stringify(value);
                }

                html += `<td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis;">${displayValue}</td>`;
            });

            html += `<td><button class="btn btn-danger" onclick='deleteItem(${JSON.stringify(item)})'>Delete</button></td></tr>`;
        });

        html += '</tbody></table></div>';

        if (data.LastEvaluatedKey) {
            html += '<p style="margin-top: 15px; color: #545B64;">Showing first 25 items. Use Query/Scan for more results.</p>';
        }

        content.innerHTML = html;

    } catch (error) {
        console.error('Error loading items:', error);
        content.innerHTML = '<p style="color: var(--danger);">Error loading items</p>';
    }
}

function showPutItemModal() {
    const example = {};
    if (currentTableKeys.partition) {
        const partitionAttr = currentTableKeys.attributes.find(a => a.AttributeName === currentTableKeys.partition);
        const partitionType = partitionAttr ? partitionAttr.AttributeType : 'S';
        example[currentTableKeys.partition] = { [partitionType]: partitionType === 'N' ? '123' : 'example-value' };
    }

    if (currentTableKeys.sort) {
        const sortAttr = currentTableKeys.attributes.find(a => a.AttributeName === currentTableKeys.sort);
        const sortType = sortAttr ? sortAttr.AttributeType : 'S';
        example[currentTableKeys.sort] = { [sortType]: sortType === 'N' ? '456' : 'sort-value' };
    }

    example.exampleAttribute = { S: 'example-data' };

    document.getElementById('item-json').value = JSON.stringify(example, null, 2);
    showModal('put-item-modal');
}

async function putItem(event) {
    event.preventDefault();
    const itemJson = document.getElementById('item-json').value;

    try {
        const item = JSON.parse(itemJson);

        await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.0',
                'X-Amz-Target': 'DynamoDB_20120810.PutItem'
            },
            body: JSON.stringify({
                TableName: currentTableName,
                Item: item
            })
        });

        closeModal('put-item-modal');
        showNotification('Item added successfully', 'success');
        loadTableItems();
    } catch (error) {
        console.error('Error putting item:', error);
        showNotification('Error adding item: ' + error.message, 'error');
    }
}

function showQueryModal() {
    document.getElementById('query-partition-value').value = '';
    document.getElementById('query-has-sort').checked = false;
    document.getElementById('query-sort-value').value = '';
    document.getElementById('query-limit').value = '';
    document.getElementById('query-results').innerHTML = '';
    toggleQuerySortKey();
    showModal('query-modal');
}

function toggleQuerySortKey() {
    const hasSort = document.getElementById('query-has-sort').checked;
    document.getElementById('query-sort-section').style.display = hasSort ? 'block' : 'none';
}

function updateQuerySortOperator() {
    const isBetween = document.getElementById('query-sort-operator').value === 'between';
    document.getElementById('query-sort-value2-group').style.display = isBetween ? 'block' : 'none';
}

async function queryItems(event) {
    event.preventDefault();
    const partitionValue = document.getElementById('query-partition-value').value;
    const hasSort = document.getElementById('query-has-sort').checked;
    const limit = document.getElementById('query-limit').value;

    const partitionAttr = currentTableKeys.attributes.find(a => a.AttributeName === currentTableKeys.partition);
    const partitionType = partitionAttr ? partitionAttr.AttributeType : 'S';

    let keyConditionExpression = `#pk = :pkval`;
    let expressionAttributeNames = {
        '#pk': currentTableKeys.partition
    };
    let expressionAttributeValues = {
        ':pkval': { [partitionType]: partitionValue }
    };

    if (hasSort && currentTableKeys.sort) {
        const sortOperator = document.getElementById('query-sort-operator').value;
        const sortValue = document.getElementById('query-sort-value').value;
        const sortAttr = currentTableKeys.attributes.find(a => a.AttributeName === currentTableKeys.sort);
        const sortType = sortAttr ? sortAttr.AttributeType : 'S';

        expressionAttributeNames['#sk'] = currentTableKeys.sort;

        if (sortOperator === 'between') {
            const sortValue2 = document.getElementById('query-sort-value2').value;
            keyConditionExpression += ` AND #sk BETWEEN :skval1 AND :skval2`;
            expressionAttributeValues[':skval1'] = { [sortType]: sortValue };
            expressionAttributeValues[':skval2'] = { [sortType]: sortValue2 };
        } else if (sortOperator === 'begins_with') {
            keyConditionExpression += ` AND begins_with(#sk, :skval)`;
            expressionAttributeValues[':skval'] = { [sortType]: sortValue };
        } else {
            keyConditionExpression += ` AND #sk ${sortOperator} :skval`;
            expressionAttributeValues[':skval'] = { [sortType]: sortValue };
        }
    }

    const requestBody = {
        TableName: currentTableName,
        KeyConditionExpression: keyConditionExpression,
        ExpressionAttributeNames: expressionAttributeNames,
        ExpressionAttributeValues: expressionAttributeValues
    };

    if (limit) {
        requestBody.Limit = parseInt(limit);
    }

    try {
        const response = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.0',
                'X-Amz-Target': 'DynamoDB_20120810.Query'
            },
            body: JSON.stringify(requestBody)
        });

        const data = await response.json();
        displayQueryResults(data.Items || [], 'query-results');
    } catch (error) {
        console.error('Error querying items:', error);
        showNotification('Error executing query: ' + error.message, 'error');
    }
}

function showScanModal() {
    document.getElementById('scan-limit').value = '';
    document.getElementById('scan-filter').value = '';
    document.getElementById('scan-results').innerHTML = '';
    showModal('scan-modal');
}

async function scanItems(event) {
    event.preventDefault();
    const limit = document.getElementById('scan-limit').value;
    const filter = document.getElementById('scan-filter').value;

    const requestBody = {
        TableName: currentTableName
    };

    if (limit) {
        requestBody.Limit = parseInt(limit);
    }

    if (filter) {
        requestBody.FilterExpression = filter;
    }

    try {
        const response = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.0',
                'X-Amz-Target': 'DynamoDB_20120810.Scan'
            },
            body: JSON.stringify(requestBody)
        });

        const data = await response.json();
        displayQueryResults(data.Items || [], 'scan-results');
    } catch (error) {
        console.error('Error scanning items:', error);
        showNotification('Error executing scan: ' + error.message, 'error');
    }
}

function displayQueryResults(items, containerId) {
    const container = document.getElementById(containerId);
    if (items.length === 0) {
        container.innerHTML = '<p>No items found</p>';
        return;
    }

    let html = `<div class="card-title">Results (${items.length} items)</div><div style="overflow-x: auto;"><table style="width: 100%;"><thead><tr>`;

    const allAttributes = new Set();
    items.forEach(item => {
        Object.keys(item).forEach(key => allAttributes.add(key));
    });

    allAttributes.forEach(attr => {
        html += `<th>${attr}</th>`;
    });
    html += `</tr></thead><tbody>`;

    items.forEach(item => {
        html += '<tr>';
        allAttributes.forEach(attr => {
            const value = item[attr];
            let displayValue = 'N/A';

            if (value) {
                if (value.S !== undefined) displayValue = value.S;
                else if (value.N !== undefined) displayValue = value.N;
                else if (value.BOOL !== undefined) displayValue = value.BOOL.toString();
                else if (value.NULL !== undefined) displayValue = 'NULL';
                else displayValue = JSON.stringify(value);
            }

            html += `<td>${displayValue}</td>`;
        });
        html += '</tr>';
    });

    html += '</tbody></table></div>';
    container.innerHTML = html;
}

async function deleteItem(item) {
    const key = {};
    if (currentTableKeys.partition && item[currentTableKeys.partition]) {
        key[currentTableKeys.partition] = item[currentTableKeys.partition];
    }

    if (currentTableKeys.sort && item[currentTableKeys.sort]) {
        key[currentTableKeys.sort] = item[currentTableKeys.sort];
    }

    showConfirmModal(
        'Are you sure you want to delete this item?',
        async () => {
            try {
                await fetch(API_BASE, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-amz-json-1.0',
                        'X-Amz-Target': 'DynamoDB_20120810.DeleteItem'
                    },
                    body: JSON.stringify({
                        TableName: currentTableName,
                        Key: key
                    })
                });

                showNotification('Item deleted successfully', 'success');
                loadTableItems();
            } catch (error) {
                console.error('Error deleting item:', error);
                showNotification('Error deleting item', 'error');
            }
        }
    );
}

async function deleteTable(tableName) {
    showConfirmModal(
        `Are you sure you want to delete table: ${tableName}?<br><br>This cannot be undone.`,
        async () => {
            try {
                await fetch(API_BASE, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-amz-json-1.0',
                        'X-Amz-Target': 'DynamoDB_20120810.DeleteTable'
                    },
                    body: JSON.stringify({ TableName: tableName })
                });
                showNotification(`Table ${tableName} deleted successfully`, 'success');
                loadTables();
            } catch (error) {
                console.error('Error deleting table:', error);
                showNotification('Error deleting table', 'error');
            }
        }
    );
}
function showCreateGSIModal(tableName) {
    currentTableName = tableName;
    document.getElementById('gsi-name').value = '';
    document.getElementById('gsi-partition-key').value = '';
    document.getElementById('gsi-partition-type').value = 'S';
    document.getElementById('gsi-has-sort').checked = false;
    document.getElementById('gsi-sort-key').value = '';
    document.getElementById('gsi-sort-type').value = 'S';
    document.getElementById('gsi-projection').value = 'ALL';
    toggleGSISortKey();
    showModal('create-gsi-modal');
}

function toggleGSISortKey() {
    const hasSort = document.getElementById('gsi-has-sort').checked;
    document.getElementById('gsi-sort-section').style.display = hasSort ? 'block' : 'none';
}

async function createGSI(event) {
    event.preventDefault();
    const indexName = document.getElementById('gsi-name').value;
    const partitionKey = document.getElementById('gsi-partition-key').value;
    const partitionType = document.getElementById('gsi-partition-type').value;
    const hasSort = document.getElementById('gsi-has-sort').checked;
    const projectionType = document.getElementById('gsi-projection').value;

    const keySchema = [{
        AttributeName: partitionKey,
        KeyType: 'HASH'
    }];

    const attributeDefinitions = [{
        AttributeName: partitionKey,
        AttributeType: partitionType
    }];

    if (hasSort) {
        const sortKey = document.getElementById('gsi-sort-key').value;
        const sortType = document.getElementById('gsi-sort-type').value;

        if (sortKey) {
            keySchema.push({
                AttributeName: sortKey,
                KeyType: 'RANGE'
            });

            attributeDefinitions.push({
                AttributeName: sortKey,
                AttributeType: sortType
            });
        }
    }

    try {
        await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.0',
                'X-Amz-Target': 'DynamoDB_20120810.UpdateTable'
            },
            body: JSON.stringify({
                TableName: currentTableName,
                AttributeDefinitions: attributeDefinitions,
                GlobalSecondaryIndexUpdates: [{
                    Create: {
                        IndexName: indexName,
                        KeySchema: keySchema,
                        Projection: {
                            ProjectionType: projectionType
                        }
                    }
                }]
            })
        });

        closeModal('create-gsi-modal');
        showNotification(`GSI ${indexName} created successfully`, 'success');
        loadTables();
    } catch (error) {
        console.error('Error creating GSI:', error);
        showNotification('Error creating GSI: ' + error.message, 'error');
    }
}

// ============================================================================
// SQS FUNCTIONS
// ============================================================================

async function loadQueues() {
    const loading = document.getElementById('sqs-loading');
    const content = document.getElementById('sqs-content');
    const empty = document.getElementById('sqs-empty');

    loading.style.display = 'block';
    content.style.display = 'none';
    empty.style.display = 'none';

    try {
        const response = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.0',
                'X-Amz-Target': 'AmazonSQS.ListQueues'
            },
            body: JSON.stringify({})
        });

        const data = await response.json();
        const queues = data.QueueUrls || [];

        if (queues.length === 0) {
            loading.style.display = 'none';
            empty.style.display = 'block';
            updateSQSStats(0);
            return;
        }

        const tbody = document.querySelector('#sqs-table tbody');
        tbody.innerHTML = '';

        let totalMessages = 0;
        let totalInFlight = 0;

        for (const queueUrl of queues) {
            const queueName = queueUrl.split('/').pop();

            const attrResponse = await fetch(API_BASE, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-amz-json-1.0',
                    'X-Amz-Target': 'AmazonSQS.GetQueueAttributes'
                },
                body: JSON.stringify({
                    QueueUrl: queueUrl,
                    AttributeNames: ['All']
                })
            });

            const attrData = await attrResponse.json();
            const attrs = attrData.Attributes || {};

            const available = parseInt(attrs.ApproximateNumberOfMessages || 0);
            const inFlight = parseInt(attrs.ApproximateNumberOfMessagesNotVisible || 0);
            totalMessages += available;
            totalInFlight += inFlight;

            const row = tbody.insertRow();
            row.innerHTML = `
                <td><strong>${queueName}</strong></td>
                <td>${available}</td>
                <td>${inFlight}</td>
                <td><span class="badge badge-info">${attrs.FifoQueue === 'true' ? 'FIFO' : 'Standard'}</span></td>
                <td>
                    <div class="action-buttons">
                        <button class="btn btn-secondary" onclick="viewQueueDetails('${queueUrl}', '${queueName}')">Details</button>
                        <button class="btn btn-primary" onclick="peekMessage('${queueUrl}', '${queueName}')">Peek</button>
                        <button class="btn btn-primary" onclick="receiveMessage('${queueUrl}', '${queueName}')">Receive</button>
                        <button class="btn btn-warning" onclick="purgeQueue('${queueUrl}', '${queueName}')">Purge</button>
                        <button class="btn btn-danger" onclick="deleteQueue('${queueUrl}', '${queueName}')">Delete</button>
                    </div>
                </td>
            `;
        }

        updateSQSStats(queues.length, totalMessages, totalInFlight);

        loading.style.display = 'none';
        content.style.display = 'block';

    } catch (error) {
        console.error('Error loading queues:', error);
        loading.innerHTML = '<p style="color: var(--danger);">Error loading queues. Is LocalStack running?</p>';
    }
}

function updateSQSStats(queueCount, totalMessages = 0, totalInFlight = 0) {
    const statsDiv = document.getElementById('sqs-stats');
    statsDiv.innerHTML = `
        <div class="stat-card">
            <div class="stat-label">Total Queues</div>
            <div class="stat-value">${queueCount}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Messages Available</div>
            <div class="stat-value">${totalMessages}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Messages In Flight</div>
            <div class="stat-value">${totalInFlight}</div>
        </div>
    `;
}

async function viewQueueDetails(queueUrl, queueName) {
    try {
        const response = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.0',
                'X-Amz-Target': 'AmazonSQS.GetQueueAttributes'
            },
            body: JSON.stringify({
                QueueUrl: queueUrl,
                AttributeNames: ['All']
            })
        });

        const data = await response.json();
        const attrs = data.Attributes || {};

        const content = document.getElementById('queue-details-content');
        content.innerHTML = `
            <div class="detail-row">
                <div class="detail-label">Queue Name</div>
                <div class="detail-value">${queueName}</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Queue URL</div>
                <div class="detail-value"><code>${queueUrl}</code></div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Queue ARN</div>
                <div class="detail-value"><code>${attrs.QueueArn || 'N/A'}</code></div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Messages Available</div>
                <div class="detail-value">${attrs.ApproximateNumberOfMessages || 0}</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Messages In Flight</div>
                <div class="detail-value">${attrs.ApproximateNumberOfMessagesNotVisible || 0}</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Visibility Timeout</div>
                <div class="detail-value">${attrs.VisibilityTimeout || 30} seconds</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Message Retention</div>
                <div class="detail-value">${attrs.MessageRetentionPeriod || 345600} seconds</div>
            </div>
        `;

        showModal('queue-details-modal');
    } catch (error) {
        console.error('Error loading queue details:', error);
        showNotification(`Error loading queue details. Error: ${error.message}`, 'error');
    }
}

function formatMessageBody(body) {
    // If it's already an object (shouldn't happen but just in case)
    if (typeof body === 'object') {
        return JSON.stringify(body, null, 2);
    }

    // Try to parse as JSON
    try {
        const parsed = JSON.parse(body);
        return JSON.stringify(parsed, null, 2);
    } catch (e) {
        // Not JSON, return as-is (plain text, XML, etc.)
        return body;
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function initEnvironmentVariablesEditor(functionName, envVars) {
    const container = document.getElementById('env-vars-container');

    const html = `
        <div class="env-vars-list" id="env-vars-list"></div>
        <div style="margin-top: 10px;">
            <button class="btn btn-primary btn-sm" onclick="addNewEnvVar()">+ Add Variable</button>
            <button class="btn btn-secondary btn-sm" id="env-cancel-btn" style="display: none;" onclick="cancelEnvVarEdits()">Cancel</button>
        </div>
    `;

    container.innerHTML = html;
    container.dataset.functionName = functionName;

    // Render existing env vars
    renderEnvVars(envVars);
}

function renderEnvVars(envVars) {
    const list = document.getElementById('env-vars-list');

    if (!envVars || Object.keys(envVars).length === 0) {
        list.innerHTML = '<div style="color: var(--text-secondary); font-style: italic;">No environment variables</div>';
        return;
    }

    let html = '';
    for (const [key, value] of Object.entries(envVars)) {
        html += createEnvVarRow(key, value, false);
    }

    list.innerHTML = html;
}

function createEnvVarRow(key, value, isEditing) {
    const rowId = `env-row-${Math.random().toString(36).substr(2, 9)}`;

    if (isEditing) {
        return `
            <div class="env-var-row editing" id="${rowId}" data-original-key="${escapeHtml(key)}" data-original-value="${escapeHtml(value)}">
                <input type="text" class="env-key-input" value="${escapeHtml(key)}" placeholder="KEY" ${key ? '' : 'autofocus'}>
                <span class="env-equals">=</span>
                <input type="text" class="env-value-input" value="${escapeHtml(value)}" placeholder="value">
                <button class="env-icon-btn" onclick="saveEnvVar('${rowId}')" title="Save">
                    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                        <path d="M13.854 3.646a.5.5 0 0 1 0 .708l-7 7a.5.5 0 0 1-.708 0l-3.5-3.5a.5.5 0 1 1 .708-.708L6.5 10.293l6.646-6.647a.5.5 0 0 1 .708 0z"/>
                    </svg>
                </button>
                <button class="env-icon-btn" onclick="deleteEnvVarRow('${rowId}')" title="Delete">
                    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                        <path d="M5.5 5.5A.5.5 0 0 1 6 6v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm2.5 0a.5.5 0 0 1 .5.5v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm3 .5a.5.5 0 0 0-1 0v6a.5.5 0 0 0 1 0V6z"/>
                        <path fill-rule="evenodd" d="M14.5 3a1 1 0 0 1-1 1H13v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V4h-.5a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1H6a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1h3.5a1 1 0 0 1 1 1v1zM4.118 4 4 4.059V13a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V4.059L11.882 4H4.118zM2.5 3V2h11v1h-11z"/>
                    </svg>
                </button>
            </div>
        `;
    } else {
        return `
            <div class="env-var-row" id="${rowId}" data-key="${escapeHtml(key)}" data-value="${escapeHtml(value)}">
                <span class="env-key">${escapeHtml(key)}</span>
                <span class="env-equals">=</span>
                <span class="env-value">${escapeHtml(value)}</span>
                <button class="env-icon-btn" onclick="editEnvVar('${rowId}')" title="Edit">
                    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                        <path d="M12.146.146a.5.5 0 0 1 .708 0l3 3a.5.5 0 0 1 0 .708l-10 10a.5.5 0 0 1-.168.11l-5 2a.5.5 0 0 1-.65-.65l2-5a.5.5 0 0 1 .11-.168l10-10zM11.207 2.5 13.5 4.793 14.793 3.5 12.5 1.207 11.207 2.5zm1.586 3L10.5 3.207 4 9.707V10h.5a.5.5 0 0 1 .5.5v.5h.5a.5.5 0 0 1 .5.5v.5h.293l6.5-6.5zm-9.761 5.175-.106.106-1.528 3.821 3.821-1.528.106-.106A.5.5 0 0 1 5 12.5V12h-.5a.5.5 0 0 1-.5-.5V11h-.5a.5.5 0 0 1-.468-.325z"/>
                    </svg>
                </button>
                <button class="env-icon-btn" onclick="deleteEnvVar('${rowId}', '${escapeHtml(key)}')" title="Delete">
                    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                        <path d="M5.5 5.5A.5.5 0 0 1 6 6v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm2.5 0a.5.5 0 0 1 .5.5v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm3 .5a.5.5 0 0 0-1 0v6a.5.5 0 0 0 1 0V6z"/>
                        <path fill-rule="evenodd" d="M14.5 3a1 1 0 0 1-1 1H13v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V4h-.5a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1H6a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1h3.5a1 1 0 0 1 1 1v1zM4.118 4 4 4.059V13a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V4.059L11.882 4H4.118zM2.5 3V2h11v1h-11z"/>
                    </svg>
                </button>
            </div>
        `;
    }
}

function addNewEnvVar() {
    const list = document.getElementById('env-vars-list');

    // Remove "no variables" message if present
    if (list.querySelector('div[style*="font-style: italic"]')) {
        list.innerHTML = '';
    }

    // Add new editable row
    list.insertAdjacentHTML('beforeend', createEnvVarRow('', '', true));

    // Show cancel button
    document.getElementById('env-cancel-btn').style.display = 'inline-block';
}

function editEnvVar(rowId) {
    const row = document.getElementById(rowId);
    const key = row.dataset.key;
    const value = row.dataset.value;

    // Replace row with editable version
    row.outerHTML = createEnvVarRow(key, value, true);

    // Show cancel button
    document.getElementById('env-cancel-btn').style.display = 'inline-block';
}

function cancelEnvVarEdits() {
    // Get current env vars from function
    const container = document.getElementById('env-vars-container');
    const functionName = container.dataset.functionName;

    // Reload function details to reset
    viewFunctionDetails(functionName);
}

async function saveEnvVar(rowId) {
    const row = document.getElementById(rowId);
    const keyInput = row.querySelector('.env-key-input');
    const valueInput = row.querySelector('.env-value-input');

    const newKey = keyInput.value.trim();
    const newValue = valueInput.value.trim();
    const originalKey = row.dataset.originalKey;

    // Validation
    if (!newKey) {
        showNotification('Environment variable key cannot be empty', 'error');
        keyInput.focus();
        return;
    }

    if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(newKey)) {
        showNotification('Key must start with letter or underscore and contain only alphanumeric characters and underscores', 'error');
        keyInput.focus();
        return;
    }

    // Check for duplicate keys (excluding the original key if editing)
    const allRows = document.querySelectorAll('.env-var-row');
    for (const otherRow of allRows) {
        if (otherRow.id === rowId) continue;

        const otherKey = otherRow.dataset.key || otherRow.querySelector('.env-key-input')?.value.trim();
        if (otherKey === newKey) {
            showNotification(`Environment variable "${newKey}" already exists`, 'error');
            keyInput.focus();
            return;
        }
    }

    // Get function name
    const container = document.getElementById('env-vars-container');
    const functionName = container.dataset.functionName;

    // Collect all current env vars
    const envVars = {};
    for (const r of allRows) {
        let k, v;
        if (r.classList.contains('editing')) {
            k = r.querySelector('.env-key-input')?.value.trim();
            v = r.querySelector('.env-value-input')?.value.trim();
        } else {
            k = r.dataset.key;
            v = r.dataset.value;
        }

        if (k) {
            envVars[k] = v;
        }
    }

    // Update with new/edited value
    if (originalKey && originalKey !== newKey) {
        delete envVars[originalKey]; // Remove old key if renamed
    }
    envVars[newKey] = newValue;

    // Update configuration
    try {
        const response = await fetch(`${API_BASE}2015-03-31/functions/${functionName}/configuration`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                Environment: {
                    Variables: envVars
                }
            })
        });

        if (!response.ok) {
            throw new Error(`Failed to update: ${response.statusText}`);
        }

        showNotification('Environment variable saved', 'success');

        // Refresh the view
        viewFunctionDetails(functionName);

    } catch (error) {
        console.error('Error saving environment variable:', error);
        showNotification('Error saving environment variable', 'error');
    }
}

async function deleteEnvVar(rowId, key) {
    showConfirmModal(
        `Delete environment variable "${key}"?`,
        async () => {
            await deleteEnvVarConfirmed(rowId, key);
        }
    );
}

async function deleteEnvVarConfirmed(rowId, key) {
    const container = document.getElementById('env-vars-container');
    const functionName = container.dataset.functionName;

    // Collect all env vars except the one being deleted
    const envVars = {};
    const allRows = document.querySelectorAll('.env-var-row');
    for (const row of allRows) {
        if (row.id === rowId) continue;

        let k, v;
        if (row.classList.contains('editing')) {
            k = row.querySelector('.env-key-input')?.value.trim();
            v = row.querySelector('.env-value-input')?.value.trim();
        } else {
            k = row.dataset.key;
            v = row.dataset.value;
        }

        if (k) {
            envVars[k] = v;
        }
    }

    try {
        const response = await fetch(`${API_BASE}2015-03-31/functions/${functionName}/configuration`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                Environment: {
                    Variables: envVars
                }
            })
        });

        if (!response.ok) {
            throw new Error(`Failed to delete: ${response.statusText}`);
        }

        showNotification('Environment variable deleted', 'success');

        // Refresh the view
        viewFunctionDetails(functionName);

    } catch (error) {
        console.error('Error deleting environment variable:', error);
        showNotification('Error deleting environment variable', 'error');
    }
}

function deleteEnvVarRow(rowId) {
    // For new unsaved rows, just remove them
    const row = document.getElementById(rowId);
    const originalKey = row.dataset.originalKey;

    if (!originalKey) {
        // New row that was never saved - just remove it
        row.remove();

        // Hide cancel button if no more editing rows
        if (!document.querySelector('.env-var-row.editing')) {
            document.getElementById('env-cancel-btn').style.display = 'none';
        }

        // Show "no variables" message if list is empty
        const list = document.getElementById('env-vars-list');
        if (list.children.length === 0) {
            list.innerHTML = '<div style="color: var(--text-secondary); font-style: italic;">No environment variables</div>';
        }
    } else {
        // Existing row being edited - revert to original
        row.outerHTML = createEnvVarRow(originalKey, row.dataset.originalValue, false);

        // Hide cancel button if no more editing rows
        if (!document.querySelector('.env-var-row.editing')) {
            document.getElementById('env-cancel-btn').style.display = 'none';
        }
    }
}

async function peekMessage(queueUrl, queueName) {
    try {
        const response = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.0',
                'X-Amz-Target': 'AmazonSQS.ReceiveMessage'
            },
            body: JSON.stringify({
                QueueUrl: queueUrl,
                MaxNumberOfMessages: 1,
                VisibilityTimeout: 0,
                WaitTimeSeconds: 0
            })
        });

        const data = await response.json();
        const messages = data.Messages || [];

        const header = document.getElementById('sqs-message-header');
        const content = document.getElementById('sqs-message-content');

        header.textContent = `Peek Message from ${queueName}`;

        if (messages.length === 0) {
            content.innerHTML = '<p>No messages available in queue</p>';
        } else {
            const msg = messages[0];
            content.innerHTML = `
                <div class="detail-row">
                    <div class="detail-label">Message ID</div>
                    <div class="detail-value"><code>${msg.MessageId}</code></div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Body</div>
                    <div class="detail-value"><pre class="code-block">${escapeHtml(formatMessageBody(msg.Body))}</pre></div>
                </div>
                ${msg.Attributes ? `
                <div class="detail-row">
                    <div class="detail-label">Attributes</div>
                    <div class="detail-value"><pre class="code-block">${escapeHtml(formatMessageBody(msg.Attributes))}</pre></div>
                </div>
                ` : ''}
                <p style="margin-top: 15px; color: #545B64; font-size: 14px;">
                    <strong>Note:</strong> Message was peeked (not deleted). It will become visible again shortly.
                </p>
            `;
        }

        showModal('sqs-message-modal');
    } catch (error) {
        console.error('Error peeking message:', error);
        showNotification(`Error peeking message. Error: ${error.message}`, 'error');
    }
}

async function receiveMessage(queueUrl, queueName) {
    try {
        const response = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.0',
                'X-Amz-Target': 'AmazonSQS.ReceiveMessage'
            },
            body: JSON.stringify({
                QueueUrl: queueUrl,
                MaxNumberOfMessages: 1,
                WaitTimeSeconds: 0
            })
        });

        const data = await response.json();
        const messages = data.Messages || [];

        const header = document.getElementById('sqs-message-header');
        const content = document.getElementById('sqs-message-content');

        header.textContent = `Receive Message from ${queueName}`;

        if (messages.length === 0) {
            content.innerHTML = '<p>No messages available in queue</p>';
        } else {
            const msg = messages[0];

            await fetch(API_BASE, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-amz-json-1.0',
                    'X-Amz-Target': 'AmazonSQS.DeleteMessage'
                },
                body: JSON.stringify({
                    QueueUrl: queueUrl,
                    ReceiptHandle: msg.ReceiptHandle
                })
            });

            content.innerHTML = `
                <div class="detail-row">
                    <div class="detail-label">Message ID</div>
                    <div class="detail-value"><code>${msg.MessageId}</code></div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Body</div>
                    <div class="detail-value"><pre class="code-block">${escapeHtml(formatMessageBody(msg.Body))}</pre></div>
                </div>
                <p style="margin-top: 15px; color: var(--success); font-size: 14px;">
                    <strong>✓ Message received and deleted from queue</strong>
                </p>
            `;

            loadQueues();
        }

        showModal('sqs-message-modal');
    } catch (error) {
        console.error('Error receiving message:', error);
        showNotification(`Error receiving message. Error: ${error.message}`, 'error');
    }
}

async function purgeQueue(queueUrl, queueName) {
    showConfirmModal(
        `Are you sure you want to purge all messages from : ${queueName}?`,
        async () => {
            try {
                await fetch(API_BASE, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-amz-json-1.0',
                        'X-Amz-Target': 'AmazonSQS.PurgeQueue'
                    },
                    body: JSON.stringify({ QueueUrl: queueUrl })
                });

                showNotification(`Queue ${queueName} purged successfully`, 'success');
                loadQueues();
            } catch (error) {
                console.error('Error purging queue:', error);
                showNotification('Error purging queue', 'error');
            }
        }
    )
}

async function deleteQueue(queueUrl, queueName) {
    showConfirmModal(
        `Are you sure you want to delete the queue: ${queueName}?This cannot be undone.`,
        async () => {
            try {
                await fetch(API_BASE, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-amz-json-1.0',
                        'X-Amz-Target': 'AmazonSQS.DeleteQueue'
                    },
                    body: JSON.stringify({ QueueUrl: queueUrl })
                });

                showNotification(`Queue ${queueName} deleted successfully`, 'success');
                loadQueues();
            } catch (error) {
                console.error('Error deleting queue:', error);
                showNotification('Error deleting queue', 'error');
            }
        }
    )
}

function showCreateQueueModal() {
    document.getElementById('queue-name').value = '';
    document.getElementById('queue-visibility').value = '30';
    document.getElementById('queue-retention').value = '345600';
    showModal('create-queue-modal');
}

async function createQueue(event) {
    event.preventDefault();

    const queueName = document.getElementById('queue-name').value;
    const visibility = document.getElementById('queue-visibility').value;
    const retention = document.getElementById('queue-retention').value;

    try {
        await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.0',
                'X-Amz-Target': 'AmazonSQS.CreateQueue'
            },
            body: JSON.stringify({
                QueueName: queueName,
                Attributes: {
                    VisibilityTimeout: visibility,
                    MessageRetentionPeriod: retention
                }
            })
        });

        closeModal('create-queue-modal');
        showNotification(`Queue ${queueName} created successfully`, 'success');
        loadQueues();
    } catch (error) {
        console.error('Error creating queue:', error);
        showNotification('Error creating queue', 'error');
    }
}

// ============================================================================
// LAMBDA FUNCTIONS
// ============================================================================

async function loadFunctions() {
    const loading = document.getElementById('lambda-loading');
    const content = document.getElementById('lambda-content');
    const empty = document.getElementById('lambda-empty');

    loading.style.display = 'block';
    content.style.display = 'none';
    empty.style.display = 'none';

    try {
        const response = await fetch(`${API_BASE}2015-03-31/functions`, {
            method: 'GET'
        });

        const data = await response.json();
        const functions = data.Functions || [];

        if (functions.length === 0) {
            loading.style.display = 'none';
            empty.style.display = 'block';
            updateLambdaStats(0);
            return;
        }

        const tbody = document.querySelector('#lambda-table tbody');
        tbody.innerHTML = '';

        let activeCount = 0;

        for (const func of functions) {
            if (func.State === 'Active') activeCount++;

            const row = tbody.insertRow();
            row.innerHTML = `
                <td><strong>${func.FunctionName}</strong></td>
                <td>${func.Runtime}</td>
                <td><span class="badge ${func.State === 'Active' ? 'badge-success' : 'badge-danger'}">${func.State}</span></td>
                <td>${new Date(func.LastModified || Date.now()).toLocaleString()}</td>
                <td>
                    <div class="action-buttons">
                        <button class="btn btn-secondary" onclick="viewFunctionDetails('${func.FunctionName}')">Details</button>
                        <button class="btn btn-primary" onclick="showTestFunctionModal('${func.FunctionName}')">Test</button>
                        <button class="btn btn-secondary" onclick="viewFunctionLogs('${func.FunctionName}')">Logs</button>
                        <button class="btn btn-secondary" onclick="viewEventSourceMappings('${func.FunctionName}')">ESM</button>
                        <button class="btn btn-danger" onclick="deleteFunction('${func.FunctionName}')">Delete</button>
                    </div>
                </td>
            `;
        }

        updateLambdaStats(functions.length, activeCount);

        loading.style.display = 'none';
        content.style.display = 'block';

    } catch (error) {
        console.error('Error loading functions:', error);
        loading.innerHTML = '<p style="color: var(--danger);">Error loading functions</p>';
    }
}

function updateLambdaStats(functionCount, activeCount = 0) {
    const statsDiv = document.getElementById('lambda-stats');
    statsDiv.innerHTML = `
        <div class="stat-card">
            <div class="stat-label">Total Functions</div>
            <div class="stat-value">${functionCount}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Active Functions</div>
            <div class="stat-value">${activeCount}</div>
        </div>
    `;
}

async function viewFunctionDetails(functionName) {
    try {
        const response = await fetch(`${API_BASE}2015-03-31/functions/${functionName}`, {
            method: 'GET'
        });

        const data = await response.json();
        const config = data.Configuration || {};

        // Construct log group name
        const logGroupName = `/aws/lambda/${config.FunctionName}`;

        const content = document.getElementById('function-details-content');
        content.innerHTML = `
            <div class="detail-row">
                <div class="detail-label">Function Name</div>
                <div class="detail-value">${escapeHtml(config.FunctionName)}</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Function ARN</div>
                <div class="detail-value"><code>${escapeHtml(config.FunctionArn || 'N/A')}</code></div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Runtime</div>
                <div class="detail-value">${escapeHtml(config.Runtime || 'N/A')}</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Handler</div>
                <div class="detail-value">${escapeHtml(config.Handler || 'N/A')}</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">State</div>
                <div class="detail-value"><span class="badge ${config.State === 'Active' ? 'badge-success' : 'badge-danger'}">${escapeHtml(config.State)}</span></div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Memory Size</div>
                <div class="detail-value">${config.MemorySize || 128} MB</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Timeout</div>
                <div class="detail-value">${config.Timeout || 3} seconds</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Log Group</div>
                <div class="detail-value">
                    <code>${escapeHtml(logGroupName)}</code>
                    <button class="btn btn-secondary" style="margin-left: 10px;" onclick="viewFunctionLogs('${escapeHtml(config.FunctionName)}')">
                        View Logs
                    </button>
                </div>
            </div>
            ${config.Description ? `
            <div class="detail-row">
                <div class="detail-label">Description</div>
                <div class="detail-value">${escapeHtml(config.Description)}</div>
            </div>
            ` : ''}
            ${config.Role ? `
            <div class="detail-row">
                <div class="detail-label">Execution Role</div>
                <div class="detail-value"><code style="font-size: 11px; word-break: break-all;">${escapeHtml(config.Role)}</code></div>
            </div>
            ` : ''}
            <div class="detail-row">
                <div class="detail-label">Environment Variables</div>
                <div class="detail-value">
                    <div id="env-vars-container"></div>
                </div>
            </div>
        `;

        // Initialize environment variables editor
        initEnvironmentVariablesEditor(config.FunctionName, config.Environment || {});

        showModal('function-details-modal');
    } catch (error) {
        console.error('Error loading function details:', error);
        showNotification('Error loading function details', 'error');
    }
}

function showTestFunctionModal(functionName) {
    document.getElementById('test-function-name').textContent = functionName;
    document.getElementById('test-payload').value = '{}';
    document.getElementById('event-name').value = '';
    document.getElementById('test-result').style.display = 'none';
    document.getElementById('test-result-content').innerHTML = '';

    // Load saved events for this function
    loadSavedEventsList(functionName);

    showModal('test-lambda-modal');
}

async function testFunction(event) {
    event.preventDefault();

    const functionName = document.getElementById('test-function-name').textContent;
    const payload = document.getElementById('test-payload').value;
    const resultDiv = document.getElementById('test-result');
    const contentDiv = document.getElementById('test-result-content');

    try {
        JSON.parse(payload);

        // Set pending until results are received
        contentDiv.innerHTML = `
                <div class="detail-row">
                    <div class="detail-label">Status</div>
                    <div class="detail-value"><span class="badge badge-waiting">Pending</span></div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Response</div>
                    <div class="detail-value"><pre class="code-block"><div class="progress"></div></pre></div>
                </div>
        `;
        resultDiv.style.display = 'block';

        const response = await fetch(`${API_BASE}2015-03-31/functions/${functionName}/invocations`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: payload
        });

        if (response.ok) {
            const result = await response.text();
            let formattedResult;
            try {
                formattedResult = JSON.stringify(JSON.parse(result), null, 2);
            } catch {
                formattedResult = result;
            }

            contentDiv.innerHTML = `
                <div class="detail-row">
                    <div class="detail-label">Status</div>
                    <div class="detail-value"><span class="badge badge-success">Success</span></div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Response</div>
                    <div class="detail-value"><pre class="code-block">${formattedResult}</pre></div>
                </div>
            `;
        } else {
            const error = await response.text();
            contentDiv.innerHTML = `
                <div class="detail-row">
                    <div class="detail-label">Status</div>
                    <div class="detail-value"><span class="badge badge-danger">Error</span></div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Error</div>
                    <div class="detail-value"><pre class="code-block" style="color: var(--danger);">${error}</pre></div>
                </div>
            `;
        }
    } catch (error) {
        const resultDiv = document.getElementById('test-result');
        const contentDiv = document.getElementById('test-result-content');
        resultDiv.style.display = 'block';
        contentDiv.innerHTML = `
            <div class="detail-row">
                <div class="detail-label">Status</div>
                <div class="detail-value"><span class="badge badge-danger">Error</span></div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Error</div>
                <div class="detail-value"><pre class="code-block" style="color: var(--danger);">${error.message}</pre></div>
            </div>
        `;
    }
}

// Lambda Test Event Payload Management
function getStorageKey(functionName) {
    return `lambda-test-events-${functionName}`;
}

function getSavedEvents(functionName) {
    const key = getStorageKey(functionName);
    const stored = localStorage.getItem(key);
    return stored ? JSON.parse(stored) : {};
}

function saveTestEvent() {
    const functionName = document.getElementById('test-function-name').textContent;
    const eventName = document.getElementById('event-name').value.trim();
    const payload = document.getElementById('test-payload').value;

    if (!eventName) {
        showNotification('Please enter a name for this test event', 'error');
        return;
    }

    try {
        JSON.parse(payload);
    } catch (e) {
        showNotification('Invalid JSON payload', 'error');
        return;
    }

    const events = getSavedEvents(functionName);
    events[eventName] = payload;

    localStorage.setItem(getStorageKey(functionName), JSON.stringify(events));

    document.getElementById('event-name').value = '';
    loadSavedEventsList(functionName);

    showNotification(`Test event "${eventName}" saved successfully`, 'success');
}

function loadSavedEvent() {
    const functionName = document.getElementById('test-function-name').textContent;
    const select = document.getElementById('saved-events-select');
    const eventName = select.value;

    if (!eventName) return;

    const events = getSavedEvents(functionName);
    const payload = events[eventName];

    if (payload) {
        document.getElementById('test-payload').value = payload;
    }
}

function deleteSavedEvent() {
    const functionName = document.getElementById('test-function-name').textContent;
    const select = document.getElementById('saved-events-select');
    const eventName = select.value;

    if (!eventName) {
        showNotification('Please select a test event to delete', 'error');
        return;
    }

    showConfirmModal(
        `Delete test event "${eventName}"?`,
        async () => {
            const events = getSavedEvents(functionName);
            delete events[eventName];

            localStorage.setItem(getStorageKey(functionName), JSON.stringify(events));

            document.getElementById('test-payload').value = '{}';
            loadSavedEventsList(functionName);
        }
    );
}

function loadSavedEventsList(functionName) {
    const events = getSavedEvents(functionName);
    const select = document.getElementById('saved-events-select');

    select.innerHTML = '<option value="">-- Select a saved event --</option>';

    Object.keys(events).sort().forEach(eventName => {
        const option = document.createElement('option');
        option.value = eventName;
        option.textContent = eventName;
        select.appendChild(option);
    });
}

function viewFunctionLogs(functionName) {
    const logGroupName = `/aws/lambda/${functionName}`;
    // const cloudwatchBtn = document.querySelector('.service-nav button:nth-child(4)');
    const cloudwatchBtn = document.getElementById('service-button-cloudwatch');
    cloudwatchBtn.click();
    setTimeout(() => {
        viewLogStreams(logGroupName);
    }, 100);
}

async function viewEventSourceMappings(functionName) {
    try {
        const response = await fetch(`${API_BASE}2015-03-31/event-source-mappings/?FunctionName=${functionName}`, {
            method: 'GET'
        });

        const data = await response.json();
        const mappings = data.EventSourceMappings || [];

        const content = document.getElementById('esm-content');

        if (mappings.length === 0) {
            content.innerHTML = '<p>No event source mappings configured for this function.</p>';
        } else {
            let html = '<table style="width:100%;"><thead><tr><th>UUID</th><th>Source</th><th>State</th><th>Batch Size</th><th>Actions</th></tr></thead><tbody>';

            for (const mapping of mappings) {
                const sourceName = mapping.EventSourceArn ? mapping.EventSourceArn.split(':').pop() : 'Unknown';
                html += `
                    <tr>
                        <td><code>${mapping.UUID}</code></td>
                        <td>${sourceName}</td>
                        <td><span class="badge ${mapping.State === 'Enabled' ? 'badge-success' : 'badge-danger'}">${mapping.State}</span></td>
                        <td>${mapping.BatchSize}</td>
                        <td>
                            <button class="btn ${mapping.State === 'Enabled' ? 'btn-warning' : 'btn-primary'}"
                                    onclick="toggleESM('${mapping.UUID}', ${mapping.State === 'Enabled'})">
                                ${mapping.State === 'Enabled' ? 'Disable' : 'Enable'}
                            </button>
                            <button class="btn btn-danger" onclick="deleteESM('${mapping.UUID}')">Delete</button>
                        </td>
                    </tr>
                `;
            }

            html += '</tbody></table>';
            content.innerHTML = html;
        }

        showModal('esm-modal');
    } catch (error) {
        console.error('Error loading event source mappings:', error);
        showNotification('Error loading event source mappings', 'error');
    }
}

async function toggleESM(uuid, currentlyEnabled) {
    try {
        await fetch(`${API_BASE}2015-03-31/event-source-mappings/${uuid}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                Enabled: !currentlyEnabled
            })
        });

        showNotification(`Event source mapping ${currentlyEnabled ? 'disabled' : 'enabled'}`, 'success');
        closeModal('esm-modal');
    } catch (error) {
        console.error('Error toggling ESM:', error);
        showNotification('Error updating event source mapping', 'error');
    }
}

async function deleteESM(uuid) {
    showConfirmModal(
        'Are you sure you want to delete this event source mapping?',
        async () => {
            try {
                await fetch(`${API_BASE}2015-03-31/event-source-mappings/${uuid}`, {
                    method: 'DELETE'
                });

                showNotification('Event source mapping deleted', 'success');
                closeModal('esm-modal');
            } catch (error) {
                console.error('Error deleting ESM:', error);
                showNotification('Error deleting event source mapping', 'error');
            }
        }
    )
}

async function deleteFunction(functionName) {
    showConfirmModal(
        `Delete the function: ${functionName}?`,
        async () => {
            try {
                await fetch(`${API_BASE}2015-03-31/functions/${functionName}`, {
                    method: 'DELETE'
                });

                showNotification(`Function ${functionName} deleted successfully`, 'success');
                loadFunctions();
            } catch (error) {
                console.error('Error deleting function:', error);
                showNotification('Error deleting function', 'error');
            }
        }
    )
}

function showCreateFunctionModal() {
    // Reset form
    document.getElementById('create-function-form').reset();
    document.getElementById('lambda-package-type').value = 'Zip';
    document.getElementById('lambda-runtime').value = 'python3.12';
    document.getElementById('lambda-handler').value = 'lambda_function.handler';
    document.getElementById('lambda-memory').value = '128';
    document.getElementById('lambda-timeout').value = '300';
    document.getElementById('lambda-custom-logging').checked = false;

    // Show/hide appropriate fields
    togglePackageTypeFields();
    toggleLoggingConfig();

    showModal('create-function-modal');
}

function togglePackageTypeFields() {
    const packageType = document.getElementById('lambda-package-type').value;

    // Zip-specific fields
    document.getElementById('runtime-group').style.display = packageType === 'Zip' ? 'block' : 'none';
    document.getElementById('handler-group').style.display = packageType === 'Zip' ? 'block' : 'none';
    document.getElementById('zipfile-group').style.display = packageType === 'Zip' ? 'block' : 'none';

    // Image-specific fields
    document.getElementById('imageuri-group').style.display = packageType === 'Image' ? 'block' : 'none';
    document.getElementById('image-config-group').style.display = packageType === 'Image' ? 'block' : 'none';

    // Update required attributes
    if (packageType === 'Zip') {
        document.getElementById('lambda-runtime').required = true;
        document.getElementById('lambda-handler').required = true;
        document.getElementById('lambda-zipfile').required = true;
        document.getElementById('lambda-image-uri').required = false;
    } else {
        document.getElementById('lambda-runtime').required = false;
        document.getElementById('lambda-handler').required = false;
        document.getElementById('lambda-zipfile').required = false;
        document.getElementById('lambda-image-uri').required = true;
    }
}

function toggleLoggingConfig() {
    const customLogging = document.getElementById('lambda-custom-logging').checked;
    document.getElementById('logging-config-group').style.display = customLogging ? 'block' : 'none';
}

async function createLambdaFunction(event) {
    event.preventDefault();

    const functionName = document.getElementById('lambda-function-name').value;
    const packageType = document.getElementById('lambda-package-type').value;
    const role = document.getElementById('lambda-role').value;
    const memory = parseInt(document.getElementById('lambda-memory').value);
    const timeout = parseInt(document.getElementById('lambda-timeout').value);

    try {
        // Build the request body
        const requestBody = {
            FunctionName: functionName,
            MemorySize: memory,
            Timeout: timeout
        };

        // Add role if provided
        if (role) {
            requestBody.Role = role;
        }

        // Handle environment variables
        const envText = document.getElementById('lambda-environment').value.trim();
        if (envText) {
            try {
                const envVars = JSON.parse(envText);
                requestBody.Environment = {
                    Variables: envVars
                };
            } catch (e) {
                showNotification('Invalid JSON in Environment Variables', 'error');
                return;
            }
        }

        // Handle logging configuration
        if (document.getElementById('lambda-custom-logging').checked) {
            const logGroup = document.getElementById('lambda-log-group').value;
            const logFormat = document.getElementById('lambda-log-format').value;
            const appLogLevel = document.getElementById('lambda-app-log-level').value;
            const sysLogLevel = document.getElementById('lambda-sys-log-level').value;

            requestBody.LoggingConfig = {
                LogFormat: logFormat,
                ApplicationLogLevel: appLogLevel,
                SystemLogLevel: sysLogLevel
            };

            if (logGroup) {
                requestBody.LoggingConfig.LogGroup = logGroup;
            }
        }

        // Handle Zip vs Image package type
        if (packageType === 'Zip') {
            const runtime = document.getElementById('lambda-runtime').value;
            const handler = document.getElementById('lambda-handler').value;
            const zipFile = document.getElementById('lambda-zipfile').files[0];

            if (!zipFile) {
                showNotification('Please select a ZIP file', 'error');
                return;
            }

            requestBody.Runtime = runtime;
            requestBody.Handler = handler;

            // Read ZIP file as base64
            const zipData = await readFileAsBase64(zipFile);
            requestBody.Code = {
                ZipFile: zipData
            };

        } else {
            // Image package type
            const imageUri = document.getElementById('lambda-image-uri').value;

            if (!imageUri) {
                showNotification('Please enter a container image URI', 'error');
                return;
            }

            requestBody.Code = {
                ImageUri: imageUri
            };

            // Add image config if provided
            const command = document.getElementById('lambda-image-command').value.trim();
            const entrypoint = document.getElementById('lambda-image-entrypoint').value.trim();
            const workdir = document.getElementById('lambda-image-workdir').value.trim();

            if (command || entrypoint || workdir) {
                requestBody.ImageConfig = {};

                if (command) {
                    try {
                        requestBody.ImageConfig.Command = JSON.parse(command);
                    } catch (e) {
                        showNotification('Invalid JSON in Command Override', 'error');
                        return;
                    }
                }

                if (entrypoint) {
                    try {
                        requestBody.ImageConfig.EntryPoint = JSON.parse(entrypoint);
                    } catch (e) {
                        showNotification('Invalid JSON in EntryPoint Override', 'error');
                        return;
                    }
                }

                if (workdir) {
                    requestBody.ImageConfig.WorkingDirectory = workdir;
                }
            }
        }

        // Make API call
        showNotification('Creating function...', 'info');

        const response = await fetch(`${API_BASE}2015-03-31/functions`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestBody)
        });

        const data = await response.json();

        if (!response.ok) {
            const errorMsg = data.message || data.errorMessage || 'Failed to create function';
            showNotification(`Error: ${errorMsg}`, 'error');
            return;
        }

        closeModal('create-function-modal');
        showNotification(`Function ${functionName} created successfully`, 'success');
        loadFunctions();

    } catch (error) {
        console.error('Error creating function:', error);
        showNotification(`Error creating function: ${error.message}`, 'error');
    }
}

// Helper function to read file as base64
function readFileAsBase64(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
            // Remove the data URL prefix (e.g., "data:application/zip;base64,")
            const base64 = reader.result.split(',')[1];
            resolve(base64);
        };
        reader.onerror = reject;
        reader.readAsDataURL(file);
    });
}

// ============================================================================
// SSM PARAMETER STORE FUNCTIONS
// ============================================================================

async function loadParameters() {
    const loading = document.getElementById('ssm-loading');
    const content = document.getElementById('ssm-content');
    const empty = document.getElementById('ssm-empty');

    loading.style.display = 'block';
    content.style.display = 'none';
    empty.style.display = 'none';

    try {
        const response = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Target': 'AmazonSSM.DescribeParameters'
            },
            body: JSON.stringify({})
        });

        const data = await response.json();
        const parameters = data.Parameters || [];

        if (parameters.length === 0) {
            loading.style.display = 'none';
            empty.style.display = 'block';
            updateSSMStats(0);
            return;
        }

        const tbody = document.querySelector('#ssm-table tbody');
        tbody.innerHTML = '';

        for (const param of parameters) {
            const row = tbody.insertRow();
            row.innerHTML = `
                <td><strong>${param.Name}</strong></td>
                <td><span class="badge badge-info">${param.Type}</span></td>
                <td>${param.Version}</td>
                <td>${new Date(param.LastModifiedDate * 1000).toLocaleString()}</td>
                <td>
                    <div class="action-buttons">
                        <button class="btn btn-secondary" onclick="showEditParameterModal('${param.Name}')">Edit</button>
                        <button class="btn btn-secondary" onclick="viewParameterDetails('${param.Name}')">Details</button>
                        <button class="btn btn-danger" onclick="deleteParameter('${param.Name}')">Delete</button>
                    </div>
                </td>
            `;
        }

        updateSSMStats(parameters.length);

        loading.style.display = 'none';
        content.style.display = 'block';

    } catch (error) {
        console.error('Error loading parameters:', error);
        loading.innerHTML = '<p style="color: var(--danger);">Error loading parameters</p>';
    }
}

function updateSSMStats(paramCount) {
    const statsDiv = document.getElementById('ssm-stats');
    statsDiv.innerHTML = `
        <div class="stat-card">
            <div class="stat-label">Total Parameters</div>
            <div class="stat-value">${paramCount}</div>
        </div>
    `;
}

async function viewParameterDetails(paramName) {
    try {
        const response = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Target': 'AmazonSSM.GetParameter'
            },
            body: JSON.stringify({
                Name: paramName,
                WithDecryption: true
            })
        });

        const data = await response.json();
        const param = data.Parameter || {};

        const content = document.getElementById('parameter-details-content');
        content.innerHTML = `
            <div class="detail-row">
                <div class="detail-label">Name</div>
                <div class="detail-value">${param.Name}</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Description</div>
                <div class="detail-value"><code>${param.Description || ''}</code></div>
            </div>
            <div class="detail-row">
                <div class="detail-label">ARN</div>
                <div class="detail-value"><code>${param.ARN || 'N/A'}</code></div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Type</div>
                <div class="detail-value"><span class="badge badge-info">${param.Type}</span></div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Version</div>
                <div class="detail-value">${param.Version}</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Last Modified</div>
                <div class="detail-value">${new Date(param.LastModifiedDate * 1000).toLocaleString()}</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Value</div>
                <div class="detail-value"><pre class="code-block">${param.Value || 'N/A'}</pre></div>
            </div>
        `;

        showModal('parameter-details-modal');
    } catch (error) {
        console.error('Error loading parameter details:', error);
        showNotification('Error loading parameter details', 'error');
    }
}

function showCreateParameterModal() {
    document.getElementById('param-name').value = '';
    document.getElementById('param-type').value = 'String';
    document.getElementById('param-value').value = '';
    document.getElementById('param-description').value = '';
    showModal('create-parameter-modal');
}

async function createParameter(event) {
    event.preventDefault();

    const paramName = document.getElementById('param-name').value;
    const paramType = document.getElementById('param-type').value;
    const paramValue = document.getElementById('param-value').value;
    const paramDescription = document.getElementById('param-description').value;

    try {
        response = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Target': 'AmazonSSM.PutParameter'
            },
            body: JSON.stringify({
                Name: paramName,
                Value: paramValue,
                Type: paramType,
                Description: paramDescription,
                Overwrite: false
            })
        });
        if (!response.ok) {
            const errorText = await response.json();
            throw new Error(errorText.message);
        }
        closeModal('create-parameter-modal');
        showNotification(`Parameter ${paramName} created successfully`, 'success');
        loadParameters();
    } catch (error) {
        console.error('Error creating parameter:', error);
        showNotification(`Error creating parameter: ${error}`, 'error');
    }
}

async function deleteParameter(paramName) {
    showConfirmModal(
        `Are you sure you want to delete the parameter: ${paramName}?`,
        async () => {
            try {
                await fetch(API_BASE, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-amz-json-1.1',
                        'X-Amz-Target': 'AmazonSSM.DeleteParameter'
                    },
                    body: JSON.stringify({
                        Name: paramName
                    })
                });

                showNotification(`Parameter ${paramName} deleted successfully`, 'success');
                loadParameters();
            } catch (error) {
                console.error('Error deleting parameter:', error);
                showNotification('Error deleting parameter', 'error');
            }
        }
    )
}

async function showEditParameterModal(paramName) {
    try {
        const response = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Target': 'AmazonSSM.GetParameter'
            },
            body: JSON.stringify({
                Name: paramName,
                WithDecryption: true
            })
        });

        const data = await response.json();
        const param = data.Parameter || {};

        document.getElementById('edit-param-name').value = param.Name;
        document.getElementById('edit-param-type').value = param.Type;
        document.getElementById('edit-param-value').value = param.Value;
        document.getElementById('edit-param-description').value = param.Description || '';

        showModal('edit-parameter-modal');
    } catch (error) {
        console.error('Error loading parameter:', error);
        showNotification('Error loading parameter for editing', 'error');
    }
}

async function updateParameter(event) {
    event.preventDefault();

    const paramName = document.getElementById('edit-param-name').value;
    const paramType = document.getElementById('edit-param-type').value;
    const paramValue = document.getElementById('edit-param-value').value;
    const paramDescription = document.getElementById('edit-param-description').value;

    try {
        const response = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Target': 'AmazonSSM.PutParameter'
            },
            body: JSON.stringify({
                Name: paramName,
                Value: paramValue,
                Type: paramType,
                Description: paramDescription,
                Overwrite: true
            })
        });

        if (!response.ok) {
            const errorText = await response.json();
            throw new Error(errorText.message);
        }

        closeModal('edit-parameter-modal');
        showNotification(`Parameter ${paramName} updated successfully`, 'success');
        loadParameters();
    } catch (error) {
        console.error('Error updating parameter:', error);
        showNotification(`Error updating parameter: ${error}`, 'error');
    }
}

// ============================================================================
// CLOUDWATCH LOGS FUNCTIONS
// ============================================================================

async function loadLogGroups() {
    const loading = document.getElementById('cloudwatch-loading');
    const content = document.getElementById('cloudwatch-content');
    const empty = document.getElementById('cloudwatch-empty');

    loading.style.display = 'block';
    content.style.display = 'none';
    empty.style.display = 'none';

    try {
        const response = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Target': 'Logs_20140328.DescribeLogGroups'
            },
            body: JSON.stringify({})
        });

        const data = await response.json();
        const logGroups = data.logGroups || [];

        if (logGroups.length === 0) {
            loading.style.display = 'none';
            empty.style.display = 'block';
            updateCloudWatchStats(0);
            return;
        }

        const tbody = document.querySelector('#cloudwatch-table tbody');
        tbody.innerHTML = '';

        for (const logGroup of logGroups) {
            const row = tbody.insertRow();
            const storageBytes = logGroup.storedBytes || 0;
            const storageMB = (storageBytes / 1024 / 1024).toFixed(2);
            const creationTime = logGroup.creationTime ? new Date(logGroup.creationTime).toLocaleString() : 'N/A';

            row.innerHTML = `
                <td style="width: 40px;">
                    <input type="checkbox" class="log-group-checkbox" value="${logGroup.logGroupName}"
                           onchange="updateLogGroupDeleteButton()">
                </td>
                <td><strong>${logGroup.logGroupName}</strong></td>
                <td>${storageMB} MB</td>
                <td>${creationTime}</td>
                <td>
                    <div class="action-buttons">
                        <button class="btn btn-secondary" onclick="viewLogStreams('${logGroup.logGroupName}')">View Streams</button>
                        <button class="btn btn-danger" onclick="deleteLogGroup('${logGroup.logGroupName}')">🗑️</button>
                    </div>
                </td>
            `;
        }

        updateCloudWatchStats(logGroups.length);

        loading.style.display = 'none';
        content.style.display = 'block';

    } catch (error) {
        console.error('Error loading log groups:', error);
        loading.innerHTML = '<p style="color: var(--danger);">Error loading log groups</p>';
    }
}

function updateCloudWatchStats(logGroupCount) {
    const statsDiv = document.getElementById('cloudwatch-stats');
    statsDiv.innerHTML = `
        <div class="stat-card">
            <div class="stat-label">Total Log Groups</div>
            <div class="stat-value">${logGroupCount}</div>
        </div>
    `;
}

function updateLogGroupDeleteButton() {
    const checkboxes = document.querySelectorAll('.log-group-checkbox:checked');
    const deleteBtn = document.getElementById('delete-selected-log-groups');
    if (deleteBtn) {
        deleteBtn.disabled = checkboxes.length === 0;
        deleteBtn.textContent = checkboxes.length > 0 ? `Delete Selected (${checkboxes.length})` : 'Delete Selected';
    }
}

function toggleAllLogGroups(checked) {
    document.querySelectorAll('.log-group-checkbox').forEach(cb => {
        cb.checked = checked;
    });
    updateLogGroupDeleteButton();
}

async function deleteSelectedLogGroups() {
    const checkboxes = document.querySelectorAll('.log-group-checkbox:checked');
    const logGroups = Array.from(checkboxes).map(cb => cb.value);

    if (logGroups.length === 0) {
        showNotification('No log groups selected', 'warning');
        return;
    }

    showConfirmModal(
        `Are you sure you want to delete '${logGroups.length}' log group(s)?`,
        async () => {
            let successCount = 0;
            let errorCount = 0;

            for (const logGroupName of logGroups) {
                try {
                    await fetch(API_BASE, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-amz-json-1.1',
                            'X-Amz-Target': 'Logs_20140328.DeleteLogGroup'
                        },
                        body: JSON.stringify({
                            logGroupName: logGroupName
                        })
                    });
                    successCount++;
                } catch (error) {
                    console.error(`Error deleting log group ${logGroupName}:`, error);
                    errorCount++;
                }
            }

            if (successCount > 0) {
                showNotification(`Deleted ${successCount} log group(s)`, 'success');
            }
            if (errorCount > 0) {
                showNotification(`Failed to delete ${errorCount} log group(s)`, 'error');
            }

            loadLogGroups();
        }
    )
}

async function deleteLogGroup(logGroupName) {
    showConfirmModal(
        `Delete log group: ${logGroupName}?`,
        async () => {
            try {
                await fetch(API_BASE, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-amz-json-1.1',
                        'X-Amz-Target': 'Logs_20140328.DeleteLogGroup'
                    },
                    body: JSON.stringify({
                        logGroupName: logGroupName
                    })
                });

                showNotification(`Log group "${logGroupName}" deleted successfully`, 'success');
                loadLogGroups();
            } catch (error) {
                console.error('Error deleting log group:', error);
                showNotification('Error deleting log group', 'error');
            }
        }
    )
}

async function viewLogStreams(logGroupName) {
    try {
        const response = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Target': 'Logs_20140328.DescribeLogStreams'
            },
            body: JSON.stringify({
                logGroupName: logGroupName,
                orderBy: 'LastEventTime',
                descending: true
            })
        });

        const data = await response.json();
        const logStreams = data.logStreams || [];

        document.getElementById('log-group-name').textContent = logGroupName;
        const content = document.getElementById('log-streams-content');

        if (logStreams.length === 0) {
            content.innerHTML = '<p>No log streams found in this log group.</p>';
        } else {
            let html = `
                <div style="margin-bottom: 15px; display: flex; gap: 10px; align-items: center;">
                    <button class="btn btn-danger" id="delete-selected-streams" onclick="deleteSelectedLogStreams('${logGroupName}')" disabled>
                        Delete Selected
                    </button>
                    <button class="btn btn-secondary" onclick="viewLogStreams('${logGroupName}')">🔄 Refresh</button>
                </div>
                <table style="width:100%;">
                    <thead>
                        <tr>
                            <th style="width: 40px;">
                                <input type="checkbox" onchange="toggleAllLogStreams(this.checked)">
                            </th>
                            <th>Log Stream Name</th>
                            <th>Last Event Time</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
            `;

            for (const stream of logStreams) {
                const lastEventTime = stream.lastEventTimestamp ? new Date(stream.lastEventTimestamp).toLocaleString() : 'N/A';
                html += `
                    <tr>
                        <td>
                            <input type="checkbox" class="log-stream-checkbox" value="${stream.logStreamName}"
                                   onchange="updateLogStreamDeleteButton()">
                        </td>
                        <td><strong>${stream.logStreamName}</strong></td>
                        <td>${lastEventTime}</td>
                        <td>
                            <div class="action-buttons">
                                <button class="btn btn-secondary" onclick="viewLogEvents('${logGroupName}', '${stream.logStreamName}')">View Events</button>
                                <button class="btn btn-danger" onclick="deleteLogStream('${logGroupName}', '${stream.logStreamName}')">🗑️</button>
                            </div>
                        </td>
                    </tr>
                `;
            }

            html += '</tbody></table>';
            content.innerHTML = html;
        }

        showModal('log-streams-modal');
    } catch (error) {
        console.error('Error loading log streams:', error);
        showNotification('Error loading log streams', 'error');
    }
}

function toggleAllLogStreams(checked) {
    document.querySelectorAll('.log-stream-checkbox').forEach(cb => {
        cb.checked = checked;
    });
    updateLogStreamDeleteButton();
}

function updateLogStreamDeleteButton() {
    const checkboxes = document.querySelectorAll('.log-stream-checkbox:checked');
    const deleteBtn = document.getElementById('delete-selected-streams');
    if (deleteBtn) {
        deleteBtn.disabled = checkboxes.length === 0;
        deleteBtn.textContent = checkboxes.length > 0 ? `Delete Selected (${checkboxes.length})` : 'Delete Selected';
    }
}

async function deleteSelectedLogStreams(logGroupName) {
    const checkboxes = document.querySelectorAll('.log-stream-checkbox:checked');
    const logStreams = Array.from(checkboxes).map(cb => cb.value);

    if (logStreams.length === 0) {
        showNotification('No log streams selected', 'warning');
        return;
    }

    showConfirmModal(
        `Are you sure you want to delete ${logStreams.length} log stream(s)?`,
        async () => {
            let successCount = 0;
            let errorCount = 0;

            for (const logStreamName of logStreams) {
                try {
                    await fetch(API_BASE, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-amz-json-1.1',
                            'X-Amz-Target': 'Logs_20140328.DeleteLogStream'
                        },
                        body: JSON.stringify({
                            logGroupName: logGroupName,
                            logStreamName: logStreamName
                        })
                    });
                    successCount++;
                } catch (error) {
                    console.error(`Error deleting log stream ${logStreamName}:`, error);
                    errorCount++;
                }
            }

            if (successCount > 0) {
                showNotification(`Deleted ${successCount} log stream(s)`, 'success');
            }
            if (errorCount > 0) {
                showNotification(`Failed to delete ${errorCount} log stream(s)`, 'error');
            }

            // Refresh the log streams view
            closeModal('log-streams-modal');
            viewLogStreams(logGroupName);
        }
    )
}

async function deleteLogStream(logGroupName, logStreamName) {
    showConfirmModal(
        `Are you sure you want to delete log stream: "${logStreamName}"?`,
        async () => {
            try {
                await fetch(API_BASE, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-amz-json-1.1',
                        'X-Amz-Target': 'Logs_20140328.DeleteLogStream'
                    },
                    body: JSON.stringify({
                        logGroupName: logGroupName,
                        logStreamName: logStreamName
                    })
                });

                showNotification(`Log stream "${logStreamName}" deleted successfully`, 'success');
                closeModal('log-streams-modal');
                viewLogStreams(logGroupName);
            } catch (error) {
                console.error('Error deleting log stream:', error);
                showNotification('Error deleting log stream', 'error');
            }
        }
    )
}

async function viewLogEvents(logGroupName, logStreamName) {
    try {
        const response = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Target': 'Logs_20140328.GetLogEvents'
            },
            body: JSON.stringify({
                logGroupName: logGroupName,
                logStreamName: logStreamName,
                startFromHead: true
            })
        });

        const data = await response.json();
        const events = data.events || [];

        document.getElementById('log-stream-name').textContent = logStreamName;
        const content = document.getElementById('log-events-content');
        content.innerHTML = '';
        if (events.length === 0) {
            content.innerHTML = '<p>No log events found in this stream.</p>';
        } else {
            // Reduce chance of code injection from logs.
            for (const event of events) {
                const timestamp = new Date(event.timestamp).toLocaleString();
                const eventDiv = document.createElement('div');
                eventDiv.style.cssText = 'border-bottom: 1px solid var(--border-color); padding: 3px 0; display: flex; align-items: flex-start;';

                const timeDiv = document.createElement('div');
                timeDiv.style.minWidth = '190px';
                timeDiv.textContent = timestamp;

                const msgDiv = document.createElement('div');
                msgDiv.className = 'code-block';
                msgDiv.style.margin = '0';
                msgDiv.textContent = event.message; // Hopefully this is safer than the original code.

                eventDiv.appendChild(timeDiv);
                eventDiv.appendChild(msgDiv);
                content.appendChild(eventDiv);
            }
        }

        showModal('log-events-modal');
    } catch (error) {
        console.error('Error loading log events:', error);
        showNotification('Error loading log events', 'error');
    }
}

// ============================================================================
// ECR FUNCTIONS
// ============================================================================

async function loadRepositories() {
    const loading = document.getElementById('ecr-loading');
    const content = document.getElementById('ecr-content');
    const empty = document.getElementById('ecr-empty');

    loading.style.display = 'block';
    content.style.display = 'none';
    empty.style.display = 'none';

    try {
        const response = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Target': 'AmazonEC2ContainerRegistry_V20150921.DescribeRepositories'
            },
            body: JSON.stringify({})
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        console.log('ECR Repositories response:', data);
        const repositories = data.repositories || [];

        if (repositories.length === 0) {
            loading.style.display = 'none';
            empty.style.display = 'block';
            updateECRStats(0, 0);
            return;
        }

        const tbody = document.querySelector('#ecr-table tbody');
        tbody.innerHTML = '';

        let totalImages = 0;

        for (const repo of repositories) {
            try {
                const imagesResponse = await fetch(API_BASE, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-amz-json-1.1',
                        'X-Amz-Target': 'AmazonEC2ContainerRegistry_V20150921.DescribeImages'
                    },
                    body: JSON.stringify({
                        repositoryName: repo.repositoryName
                    })
                });

                const imagesData = await imagesResponse.json();
                console.log(`Images for ${repo.repositoryName}:`, imagesData);
                const imageCount = (imagesData.imageDetails || []).length;
                totalImages += imageCount;

                const createdDate = repo.createdAt ? new Date(repo.createdAt).toLocaleString() : 'N/A';

                const row = tbody.insertRow();
                row.innerHTML = `
                    <td><strong>${repo.repositoryName}</strong></td>
                    <td><code style="font-size: 12px;">${repo.repositoryUri}</code></td>
                    <td>${imageCount}</td>
                    <td>${createdDate}</td>
                    <td>
                        <div class="action-buttons">
                            <button class="btn btn-secondary" onclick="viewRepositoryImages('${repo.repositoryName}')">View Images</button>
                            <button class="btn btn-danger" onclick="deleteRepository('${repo.repositoryName}', ${imageCount > 0})">Delete</button>
                        </div>
                    </td>
                `;
            } catch (imageError) {
                console.error(`Error loading images for ${repo.repositoryName}:`, imageError);
                const row = tbody.insertRow();
                row.innerHTML = `
                    <td><strong>${repo.repositoryName}</strong></td>
                    <td><code style="font-size: 12px;">${repo.repositoryUri}</code></td>
                    <td>Error</td>
                    <td>${repo.createdAt ? new Date(repo.createdAt).toLocaleString() : 'N/A'}</td>
                    <td>
                        <div class="action-buttons">
                            <button class="btn btn-secondary" onclick="viewRepositoryImages('${repo.repositoryName}')">View Images</button>
                            <button class="btn btn-danger" onclick="deleteRepository('${repo.repositoryName}', false)">Delete</button>
                        </div>
                    </td>
                `;
            }
        }

        updateECRStats(repositories.length, totalImages);

        loading.style.display = 'none';
        content.style.display = 'block';

    } catch (error) {
        console.error('Error loading repositories:', error);
        loading.innerHTML = `<p style="color: var(--danger);">Error loading repositories: ${error.message}</p>`;
    }
}

function updateECRStats(repoCount, imageCount) {
    const statsDiv = document.getElementById('ecr-stats');
    statsDiv.innerHTML = `
        <div class="stat-card">
            <div class="stat-label">Total Repositories</div>
            <div class="stat-value">${repoCount}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Total Images</div>
            <div class="stat-value">${imageCount}</div>
        </div>
    `;
}

function showCreateRepositoryModal() {
    document.getElementById('repo-name').value = '';
    document.getElementById('repo-scan-on-push').checked = false;
    showModal('create-repository-modal');
}

async function createRepository(event) {
    event.preventDefault();

    const repoName = document.getElementById('repo-name').value;
    const scanOnPush = document.getElementById('repo-scan-on-push').checked;

    try {
        const response = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Target': 'AmazonEC2ContainerRegistry_V20150921.CreateRepository'
            },
            body: JSON.stringify({
                repositoryName: repoName,
                imageScanningConfiguration: {
                    scanOnPush: scanOnPush
                }
            })
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.message || 'Failed to create repository');
        }

        closeModal('create-repository-modal');
        showNotification(`Repository ${repoName} created successfully`, 'success');
        loadRepositories();
    } catch (error) {
        console.error('Error creating repository:', error);
        showNotification('Error creating repository: ' + error.message, 'error');
    }
}

async function viewRepositoryImages(repositoryName) {
    try {
        const response = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Target': 'AmazonEC2ContainerRegistry_V20150921.DescribeImages'
            },
            body: JSON.stringify({
                repositoryName: repositoryName
            })
        });

        if (!response.ok) {
            throw new Error(`Failed to load images: ${response.statusText}`);
        }

        const data = await response.json();
        console.log('Repository images response:', data);
        const images = data.imageDetails || [];

        document.getElementById('repo-images-name').textContent = repositoryName;
        const content = document.getElementById('repository-images-content');

        if (images.length === 0) {
            content.innerHTML = '<p>No images found in this repository.</p>';
        } else {
            let html = '<table style="width:100%;"><thead><tr><th>Image Digest</th><th>Tags</th><th>Size (MB)</th><th>Pushed At</th><th>Actions</th></tr></thead><tbody>';

            for (const image of images) {
                const digest = image.imageDigest ? image.imageDigest.substring(7, 19) + '...' : 'N/A';
                const fullDigest = image.imageDigest || '';
                const tags = (image.imageTags && image.imageTags.length > 0) ? image.imageTags.join(', ') : '<i>Untagged</i>';
                const sizeMB = image.imageSizeInBytes ? (image.imageSizeInBytes / 1024 / 1024).toFixed(2) : 'N/A';
                const pushedAt = image.imagePushedAt ? new Date(image.imagePushedAt).toLocaleString() : 'N/A';

                const imageTag = (image.imageTags && image.imageTags.length > 0) ? image.imageTags[0] : null;

                html += `
                    <tr>
                        <td><code title="${fullDigest}">${digest}</code></td>
                        <td>${tags}</td>
                        <td>${sizeMB}</td>
                        <td>${pushedAt}</td>
                        <td>
                            <div class="action-buttons">
                                <button class="btn btn-secondary" onclick='viewImageDetails(${JSON.stringify(repositoryName)}, ${JSON.stringify(image)})'>Details</button>
                                <button class="btn btn-danger" onclick='deleteImage(${JSON.stringify(repositoryName)}, ${JSON.stringify(fullDigest)}, ${JSON.stringify(imageTag)})'>Delete</button>
                            </div>
                        </td>
                    </tr>
                `;
            }

            html += '</tbody></table>';
            content.innerHTML = html;
        }

        showModal('repository-images-modal');
    } catch (error) {
        console.error('Error loading repository images:', error);
        showNotification('Error loading repository images: ' + error.message, 'error');
    }
}

async function viewImageDetails(repositoryName, image) {
    const content = document.getElementById('image-details-content');

    const imageTags = (image.imageTags && image.imageTags.length > 0) ? image.imageTags.join(', ') : 'None';
    const sizeMB = image.imageSizeInBytes ? (image.imageSizeInBytes / 1024 / 1024).toFixed(2) : 'N/A';
    const pushedAt = image.imagePushedAt ? new Date(image.imagePushedAt).toLocaleString() : 'N/A';

    content.innerHTML = `
        <div class="detail-row">
            <div class="detail-label">Repository</div>
            <div class="detail-value">${repositoryName}</div>
        </div>
        <div class="detail-row">
            <div class="detail-label">Image Digest</div>
            <div class="detail-value"><code style="font-size: 11px; word-break: break-all;">${image.imageDigest || 'N/A'}</code></div>
        </div>
        <div class="detail-row">
            <div class="detail-label">Image Tags</div>
            <div class="detail-value">${imageTags}</div>
        </div>
        <div class="detail-row">
            <div class="detail-label">Size</div>
            <div class="detail-value">${sizeMB} MB (${image.imageSizeInBytes || 0} bytes)</div>
        </div>
        <div class="detail-row">
            <div class="detail-label">Pushed At</div>
            <div class="detail-value">${pushedAt}</div>
        </div>
        ${image.registryId ? `
        <div class="detail-row">
            <div class="detail-label">Registry ID</div>
            <div class="detail-value">${image.registryId}</div>
        </div>
        ` : ''}
    `;

    showModal('image-details-modal');
}

async function deleteImage(repositoryName, imageDigest, imageTag) {
    const tagInfo = imageTag ? ` (tag: ${imageTag})` : '';

    showConfirmModal(
        `Are you sure you want to delete this image${tagInfo} from ${repositoryName}?`,
        async () => {
            try {
                const imageIds = [];

                if (imageTag) {
                    imageIds.push({ imageTag: imageTag });
                } else if (imageDigest) {
                    imageIds.push({ imageDigest: imageDigest });
                }

                const response = await fetch(API_BASE, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-amz-json-1.1',
                        'X-Amz-Target': 'AmazonEC2ContainerRegistry_V20150921.BatchDeleteImage'
                    },
                    body: JSON.stringify({
                        repositoryName: repositoryName,
                        imageIds: imageIds
                    })
                });

                const result = await response.json();

                if (!response.ok || (result.failures && result.failures.length > 0)) {
                    const errorMsg = result.failures ? result.failures[0].failureReason : 'Unknown error';
                    throw new Error(errorMsg);
                }

                showNotification('Image deleted successfully', 'success');
                closeModal('repository-images-modal');
                loadRepositories();
            } catch (error) {
                console.error('Error deleting image:', error);
                showNotification('Error deleting image: ' + error.message, 'error');
            }
        }
    )
}

async function deleteRepository(repositoryName, hasImages) {
    const forceWarning = hasImages ? '\n\nThis repository contains images. They will be deleted along with the repository.' : '';

    showConfirmModal(
        `Are you sure you want to delete repository: ${repositoryName}?${forceWarning}\n\nThis cannot be undone.`,
        async () => {
            try {
                const response = await fetch(API_BASE, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-amz-json-1.1',
                        'X-Amz-Target': 'AmazonEC2ContainerRegistry_V20150921.DeleteRepository'
                    },
                    body: JSON.stringify({
                        repositoryName: repositoryName,
                        force: hasImages
                    })
                });

                const result = await response.json();

                if (!response.ok) {
                    throw new Error(result.message || 'Failed to delete repository');
                }

                showNotification(`Repository ${repositoryName} deleted successfully`, 'success');
                loadRepositories();
            } catch (error) {
                console.error('Error deleting repository:', error);
                showNotification('Error deleting repository: ' + error.message, 'error');
            }
        }
    )
}

// ============================================================================
// S3 FUNCTIONS
// ============================================================================

function showConfigureNotificationsModal(bucketName) {
    document.getElementById('notification-bucket-name').textContent = bucketName;
    document.getElementById('configure-notifications-form').reset();
    document.getElementById('notification-destination-group').style.display = 'none';
    document.getElementById('prefix-filter-section').style.display = 'none';
    showModal('configure-notifications-modal');
}

function updateNotificationDestination() {
    const type = document.getElementById('notification-type').value;
    const group = document.getElementById('notification-destination-group');
    const label = document.getElementById('notification-destination-label');
    const input = document.getElementById('notification-destination');

    if (type) {
        group.style.display = 'block';

        if (type === 'Queue') {
            label.textContent = 'SQS Queue ARN *';
            input.placeholder = 'arn:aws:sqs:us-east-1:000000000000:my-queue';
            // } else if (type === 'Topic') {
            //     label.textContent = 'SNS Topic ARN *';
            //     input.placeholder = 'arn:aws:sns:us-east-1:000000000000:my-topic';
        } else if (type === 'Lambda') {
            label.textContent = 'Lambda Function ARN *';
            input.placeholder = 'arn:aws:lambda:us-east-1:000000000000:function:my-function';
        }
    } else {
        group.style.display = 'none';
    }
}

function togglePrefixFilter() {
    const useFilter = document.getElementById('use-prefix-filter').checked;
    document.getElementById('prefix-filter-section').style.display = useFilter ? 'block' : 'none';
}

async function configureNotifications(event) {
    event.preventDefault();

    const bucketName = document.getElementById('notification-bucket-name').textContent;
    const type = document.getElementById('notification-type').value;
    const destination = document.getElementById('notification-destination').value;
    const notificationId = document.getElementById('notification-id').value || `notification-${Date.now()}`;

    // Get selected events
    const eventCheckboxes = document.querySelectorAll('.event-checkbox:checked');
    const events = Array.from(eventCheckboxes).map(cb => cb.value);

    if (events.length === 0) {
        showNotification('Please select at least one event type', 'error');
        return;
    }

    // Build notification configuration
    const config = {
        Id: notificationId,
        Events: events
    };

    // Add destination based on type
    if (type === 'Queue') {
        config.QueueArn = destination;
    } else if (type === 'Topic') {
        config.TopicArn = destination;
    } else if (type === 'Lambda') {
        config.LambdaFunctionArn = destination;
    }

    // Add filters if specified
    const useFilter = document.getElementById('use-prefix-filter').checked;
    if (useFilter) {
        const prefix = document.getElementById('notification-prefix').value;
        const suffix = document.getElementById('notification-suffix').value;

        if (prefix || suffix) {
            config.Filter = {
                Key: {
                    FilterRules: []
                }
            };

            if (prefix) {
                config.Filter.Key.FilterRules.push({
                    Name: 'prefix',
                    Value: prefix
                });
            }

            if (suffix) {
                config.Filter.Key.FilterRules.push({
                    Name: 'suffix',
                    Value: suffix
                });
            }
        }
    }

    try {
        const response = await fetch(`${API_BASE}s3/buckets/${bucketName}/notification`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                type: type,
                configuration: config
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.message || 'Failed to configure notification');
        }

        closeModal('configure-notifications-modal');
        showNotification('Event notification configured successfully', 'success');

        // Refresh bucket details
        viewBucketDetails(bucketName);
    } catch (error) {
        console.error('Error configuring notification:', error);
        showNotification('Error configuring notification: ' + error.message, 'error');
    }
}

// let transitionCounter = 0;
// let noncurrentTransitionCounter = 0;

function showConfigureLifecycleModal(bucketName) {
    document.getElementById('lifecycle-bucket-name').textContent = bucketName;
    document.getElementById('configure-lifecycle-form').reset();

    // Reset counters and containers
    // transitionCounter = 0;
    // noncurrentTransitionCounter = 0;
    // document.getElementById('transitions-container').innerHTML = '';
    // document.getElementById('noncurrent-transitions-container').innerHTML = '';

    // Hide all conditional sections
    document.getElementById('lifecycle-prefix-group').style.display = 'none';
    document.getElementById('lifecycle-tags-group').style.display = 'none';
    // document.getElementById('transition-actions').style.display = 'none';
    document.getElementById('expiration-actions').style.display = 'none';
    // document.getElementById('noncurrent-transition-actions').style.display = 'none';
    document.getElementById('noncurrent-expiration-actions').style.display = 'none';
    document.getElementById('abort-multipart-actions').style.display = 'none';

    showModal('configure-lifecycle-modal');
}

function toggleLifecycleScope() {
    const scopeType = document.querySelector('input[name="scope-type"]:checked').value;
    document.getElementById('lifecycle-prefix-group').style.display = scopeType === 'prefix' ? 'block' : 'none';
    document.getElementById('lifecycle-tags-group').style.display = scopeType === 'tags' ? 'block' : 'none';
}

// function toggleTransitionActions() {
//     const enabled = document.getElementById('enable-transition').checked;
//     document.getElementById('transition-actions').style.display = enabled ? 'block' : 'none';
//     if (enabled && document.getElementById('transitions-container').children.length === 0) {
//         addTransition();
//     }
// }

function toggleExpirationActions() {
    const enabled = document.getElementById('enable-expiration').checked;
    document.getElementById('expiration-actions').style.display = enabled ? 'block' : 'none';
}

function toggleExpirationType() {
    const expirationType = document.querySelector('input[name="expiration-type"]:checked').value;
    document.getElementById('expiration-days-group').style.display = expirationType === 'days' ? 'block' : 'none';
    document.getElementById('expiration-date-group').style.display = expirationType === 'date' ? 'block' : 'none';
}

// function toggleNoncurrentTransitionActions() {
//     const enabled = document.getElementById('enable-noncurrent-transition').checked;
//     document.getElementById('noncurrent-transition-actions').style.display = enabled ? 'block' : 'none';
//     if (enabled && document.getElementById('noncurrent-transitions-container').children.length === 0) {
//         addNoncurrentTransition();
//     }
// }

function toggleNoncurrentExpirationActions() {
    const enabled = document.getElementById('enable-noncurrent-expiration').checked;
    document.getElementById('noncurrent-expiration-actions').style.display = enabled ? 'block' : 'none';
}

function toggleAbortMultipartActions() {
    const enabled = document.getElementById('enable-abort-multipart').checked;
    document.getElementById('abort-multipart-actions').style.display = enabled ? 'block' : 'none';
}

// function addTransition() {
//     const container = document.getElementById('transitions-container');
//     const id = transitionCounter++;

//     const div = document.createElement('div');
//     div.className = 'form-group';
//     div.id = `transition-${id}`;
//     div.style.padding = '15px';
//     div.style.border = '1px solid var(--border)';
//     div.style.borderRadius = '4px';
//     div.style.marginBottom = '10px';
//     div.style.background = '#fafafa';

//     div.innerHTML = `
//         <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
//             <strong>Transition ${id + 1}</strong>
//             <button type="button" class="btn btn-danger" onclick="removeTransition(${id})" style="padding: 4px 8px; font-size: 12px;">Remove</button>
//         </div>
//         <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
//             <div>
//                 <label style="font-size: 13px;">Days After Creation *</label>
//                 <input type="number" id="transition-days-${id}" min="1" placeholder="30" required style="width: 100%; padding: 8px;">
//             </div>
//             <div>
//                 <label style="font-size: 13px;">Storage Class *</label>
//                 <select id="transition-storage-${id}" required style="width: 100%; padding: 8px;">
//                     <option value="">-- Select --</option>
//                     <option value="STANDARD_IA">Standard-IA</option>
//                     <option value="ONEZONE_IA">One Zone-IA</option>
//                     <option value="INTELLIGENT_TIERING">Intelligent-Tiering</option>
//                     <option value="GLACIER">Glacier Flexible Retrieval</option>
//                     <option value="GLACIER_IR">Glacier Instant Retrieval</option>
//                     <option value="DEEP_ARCHIVE">Glacier Deep Archive</option>
//                 </select>
//             </div>
//         </div>
//     `;

//     container.appendChild(div);
// }

// function removeTransition(id) {
//     const element = document.getElementById(`transition-${id}`);
//     if (element) {
//         element.remove();
//     }
// }

// function addNoncurrentTransition() {
//     const container = document.getElementById('noncurrent-transitions-container');
//     const id = noncurrentTransitionCounter++;

//     const div = document.createElement('div');
//     div.className = 'form-group';
//     div.id = `noncurrent-transition-${id}`;
//     div.style.padding = '15px';
//     div.style.border = '1px solid var(--border)';
//     div.style.borderRadius = '4px';
//     div.style.marginBottom = '10px';
//     div.style.background = '#fafafa';

//     div.innerHTML = `
//         <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
//             <strong>Noncurrent Transition ${id + 1}</strong>
//             <button type="button" class="btn btn-danger" onclick="removeNoncurrentTransition(${id})" style="padding: 4px 8px; font-size: 12px;">Remove</button>
//         </div>
//         <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
//             <div>
//                 <label style="font-size: 13px;">Days After Becoming Noncurrent *</label>
//                 <input type="number" id="noncurrent-transition-days-${id}" min="1" placeholder="30" required style="width: 100%; padding: 8px;">
//             </div>
//             <div>
//                 <label style="font-size: 13px;">Storage Class *</label>
//                 <select id="noncurrent-transition-storage-${id}" required style="width: 100%; padding: 8px;">
//                     <option value="">-- Select --</option>
//                     <option value="STANDARD_IA">Standard-IA</option>
//                     <option value="ONEZONE_IA">One Zone-IA</option>
//                     <option value="INTELLIGENT_TIERING">Intelligent-Tiering</option>
//                     <option value="GLACIER">Glacier Flexible Retrieval</option>
//                     <option value="GLACIER_IR">Glacier Instant Retrieval</option>
//                     <option value="DEEP_ARCHIVE">Glacier Deep Archive</option>
//                 </select>
//             </div>
//         </div>
//         <div style="margin-top: 10px;">
//             <label style="font-size: 13px;">Number of Newer Versions to Retain</label>
//             <input type="number" id="noncurrent-transition-newer-${id}" min="1" placeholder="Leave empty for all" style="width: 100%; padding: 8px;">
//         </div>
//     `;

//     container.appendChild(div);
// }

// function removeNoncurrentTransition(id) {
//     const element = document.getElementById(`noncurrent-transition-${id}`);
//     if (element) {
//         element.remove();
//     }
// }

async function configureLifecycle(event) {
    event.preventDefault();

    const bucketName = document.getElementById('lifecycle-bucket-name').textContent;
    const ruleId = document.getElementById('lifecycle-rule-id').value;
    const status = document.getElementById('lifecycle-status').value;

    // Build the lifecycle rule
    const rule = {
        ID: ruleId,
        Status: status
    };

    // Add scope/filter
    const scopeType = document.querySelector('input[name="scope-type"]:checked').value;

    if (scopeType === 'all') {
        rule.Prefix = '';
    } else if (scopeType === 'prefix') {
        rule.Prefix = document.getElementById('lifecycle-prefix').value || '';
    } else if (scopeType === 'tags') {
        const tagsText = document.getElementById('lifecycle-tags').value.trim();
        if (tagsText) {
            const tags = tagsText.split('\n').map(line => {
                const [key, value] = line.split('=').map(s => s.trim());
                return { Key: key, Value: value };
            }).filter(tag => tag.Key && tag.Value);

            if (tags.length > 0) {
                rule.Filter = {
                    And: {
                        Tags: tags
                    }
                };
            }
        }
    }

    // Add transitions
    // if (document.getElementById('enable-transition').checked) {
    //     const transitions = [];
    //     // for (let i = 0; i < transitionCounter; i++) {
    //     //     const daysInput = document.getElementById(`transition-days-${i}`);
    //     //     const storageInput = document.getElementById(`transition-storage-${i}`);

    //     //     if (daysInput && storageInput && daysInput.value && storageInput.value) {
    //     //         transitions.push({
    //     //             Days: parseInt(daysInput.value),
    //     //             StorageClass: storageInput.value
    //     //         });
    //     //     }
    //     // }

    //     // if (transitions.length > 0) {
    //     //     rule.Transitions = transitions;
    //     // }
    // }

    // Add expiration
    if (document.getElementById('enable-expiration').checked) {
        const expirationType = document.querySelector('input[name="expiration-type"]:checked').value;
        rule.Expiration = {};

        if (expirationType === 'days') {
            const days = document.getElementById('expiration-days').value;
            if (days) {
                rule.Expiration.Days = parseInt(days);
            }
        } else if (expirationType === 'date') {
            const date = document.getElementById('expiration-date').value;
            if (date) {
                rule.Expiration.Date = new Date(date).toISOString();
            }
        }

        if (document.getElementById('expiration-expired-delete-marker').checked) {
            rule.Expiration.ExpiredObjectDeleteMarker = true;
        }
    }

    // Add noncurrent version transitions
    // if (document.getElementById('enable-noncurrent-transition').checked) {
    //     const noncurrentTransitions = [];
    //     for (let i = 0; i < noncurrentTransitionCounter; i++) {
    //         const daysInput = document.getElementById(`noncurrent-transition-days-${i}`);
    //         const storageInput = document.getElementById(`noncurrent-transition-storage-${i}`);
    //         const newerInput = document.getElementById(`noncurrent-transition-newer-${i}`);

    //         if (daysInput && storageInput && daysInput.value && storageInput.value) {
    //             const transition = {
    //                 NoncurrentDays: parseInt(daysInput.value),
    //                 StorageClass: storageInput.value
    //             };

    //             if (newerInput && newerInput.value) {
    //                 transition.NewerNoncurrentVersions = parseInt(newerInput.value);
    //             }

    //             noncurrentTransitions.push(transition);
    //         }
    //     }

    //     if (noncurrentTransitions.length > 0) {
    //         rule.NoncurrentVersionTransitions = noncurrentTransitions;
    //     }
    // }

    // Add noncurrent version expiration
    if (document.getElementById('enable-noncurrent-expiration').checked) {
        const days = document.getElementById('noncurrent-expiration-days').value;
        const newerVersions = document.getElementById('noncurrent-newer-versions').value;

        if (days) {
            rule.NoncurrentVersionExpiration = {
                NoncurrentDays: parseInt(days)
            };

            if (newerVersions) {
                rule.NoncurrentVersionExpiration.NewerNoncurrentVersions = parseInt(newerVersions);
            }
        }
    }

    // Add abort incomplete multipart upload
    if (document.getElementById('enable-abort-multipart').checked) {
        const days = document.getElementById('abort-multipart-days').value;
        if (days) {
            rule.AbortIncompleteMultipartUpload = {
                DaysAfterInitiation: parseInt(days)
            };
        }
    }

    // Validate that at least one action is configured
    const hasActions = rule.Transitions || rule.Expiration || rule.NoncurrentVersionTransitions ||
        rule.NoncurrentVersionExpiration || rule.AbortIncompleteMultipartUpload;

    if (!hasActions) {
        showNotification('Please configure at least one lifecycle action', 'error');
        return;
    }

    try {
        const response = await fetch(`${API_BASE}s3/buckets/${bucketName}/lifecycle`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ rule: rule })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.message || 'Failed to configure lifecycle rule');
        }

        closeModal('configure-lifecycle-modal');
        showNotification('Lifecycle rule configured successfully', 'success');

        // Refresh bucket details
        viewBucketDetails(bucketName);
    } catch (error) {
        console.error('Error configuring lifecycle rule:', error);
        showNotification('Error configuring lifecycle rule: ' + error.message, 'error');
    }
}

async function viewBucketDetails(bucketName) {
    try {
        document.getElementById('bucket-details-name').textContent = bucketName;
        const content = document.getElementById('bucket-details-content');
        content.innerHTML = '<div class="loading"><div class="spinner"></div><div>Loading bucket details...</div></div>';

        showModal('bucket-details-modal');

        // Fetch lifecycle policies
        let lifecyclePolicies = [];
        try {
            const lifecycleResponse = await fetch(`${API_BASE}s3/buckets/${bucketName}/lifecycle`);
            if (lifecycleResponse.ok) {
                const lifecycleData = await lifecycleResponse.json();
                lifecyclePolicies = lifecycleData.Rules || [];
            }
        } catch (error) {
            console.log('No lifecycle policies configured');
        }

        // Fetch notification configurations
        let notificationConfig = null;
        try {
            const notificationResponse = await fetch(`${API_BASE}s3/buckets/${bucketName}/notification`);
            if (notificationResponse.ok) {
                notificationConfig = await notificationResponse.json();
            }
        } catch (error) {
            console.log('No notification configurations');
        }

        // Build the details HTML
        let html = `
            <div class="detail-row">
                <div class="detail-label">Bucket Name</div>
                <div class="detail-value"><strong>${bucketName}</strong></div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Region</div>
                <div class="detail-value">${S3_CONFIG.region}</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Endpoint</div>
                <div class="detail-value"><code>${S3_CONFIG.endpoint}/${bucketName}</code></div>
            </div>
        `;

        // Lifecycle Policies Section
        html += `
            <h3 style="margin-top: 30px; margin-bottom: 15px; color: var(--text-primary);">Lifecycle Policies</h3>
        `;
        html += `
            <div style="margin-bottom: 15px;">
                <button class="btn btn-primary" onclick="showConfigureLifecycleModal('${bucketName}')">
                    Add Lifecycle Rule
                </button>
            </div>
        `;
        if (lifecyclePolicies.length === 0) {
            html += `<p style="color: var(--text-primary); font-style: italic;">No lifecycle policies configured</p>`;
        } else {
            html += `<table style="width: 100%; margin-bottom: 20px;">
                <thead>
                    <tr>
                        <th>Rule ID</th>
                        <th>Status</th>
                        <th>Prefix/Filter</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>`;

            for (const rule of lifecyclePolicies) {
                const ruleId = rule.ID || 'N/A';
                const status = rule.Status || 'Unknown';
                const prefix = rule.Prefix || (rule.Filter?.Prefix) || 'All objects';

                let actions = [];
                if (rule.Expiration) {
                    if (rule.Expiration.Days) {
                        actions.push(`Delete after ${rule.Expiration.Days} days`);
                    }
                    if (rule.Expiration.Date) {
                        actions.push(`Delete on ${rule.Expiration.Date}`);
                    }
                }
                if (rule.Transitions) {
                    for (const transition of rule.Transitions) {
                        actions.push(`Transition to ${transition.StorageClass} after ${transition.Days} days`);
                    }
                }
                if (rule.NoncurrentVersionExpiration) {
                    actions.push(`Delete noncurrent versions after ${rule.NoncurrentVersionExpiration.NoncurrentDays} days`);
                }

                const actionsText = actions.length > 0 ? actions.join('<br>') : 'None';

                html += `
                    <tr>
                        <td><code>${ruleId}</code></td>
                        <td><span class="badge ${status === 'Enabled' ? 'badge-success' : 'badge-danger'}">${status}</span></td>
                        <td>${prefix}</td>
                        <td style="font-size: 13px;">${actionsText}</td>
                        <td>
                            <button class="btn btn-danger" onclick="deleteLifecycleRule('${bucketName}', '${ruleId}')">Delete</button>
                        </td>
                    </tr>
                `;
            }

            html += `</tbody></table>`;
        }

        // Notification Configuration Section
        html += `
            <h3 style="margin-top: 30px; margin-bottom: 15px; color: var(--text-primary);">Event Notifications</h3>
        `;

        html += `
            <div style="margin: 20px 0;">
                <button class="btn btn-primary" onclick="showConfigureNotificationsModal('${bucketName}')">
                    Configure Event Notifications
                </button>
            </div>
        `;
        let hasNotifications = false;

        if (notificationConfig) {
            // SQS Queue Configurations
            if (notificationConfig.QueueConfigurations && notificationConfig.QueueConfigurations.length > 0) {
                hasNotifications = true;
                html += `
                    <h4 style="margin-top: 20px; margin-bottom: 10px; font-size: 16px;">SQS Queue Notifications</h4>
                    <table style="width: 100%; margin-bottom: 20px;">
                        <thead>
                            <tr>
                                <th>Queue ARN</th>
                                <th>Events</th>
                                <th>Filter</th>
                                <th>Suffix</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>`;

                for (const config of notificationConfig.QueueConfigurations) {
                    const queueArn = config.QueueArn || 'N/A';
                    const queueName = queueArn.split(':').pop();
                    const events = config.Events ? config.Events.join(', ') : 'None';
                    const filter = config.Filter?.Key?.FilterRules?.[0] ?
                        `${config.Filter.Key.FilterRules[0].Name}: ${config.Filter.Key.FilterRules[0].Value}` :
                        'All objects';
                    const suffix = config.Filter?.Key?.FilterRules?.[0] ?
                        `${config.Filter.Key.FilterRules[1].Name}: ${config.Filter.Key.FilterRules[1].Value}` :
                        'All objects';
                    html += `
                        <tr>
                            <td>
                                <div><strong>${queueName}</strong></div>
                                <div style="font-size: 11px; color: var(--text-primary); margin-top: 4px;"><code>${queueArn}</code></div>
                            </td>
                            <td style="font-size: 13px;">${events}</td>
                            <td style="font-size: 13px;">${filter}</td>
                            <td style="font-size: 13px;">${suffix}</td>
                            <td>
                                <button class="btn btn-danger" onclick="deleteNotification('${bucketName}', '${config.Id}')">Delete</button>
                            </td>
                        </tr>
                    `;
                }

                html += `</tbody></table>`;
            }

            // Lambda Function Configurations
            if (notificationConfig.LambdaFunctionConfigurations && notificationConfig.LambdaFunctionConfigurations.length > 0) {
                hasNotifications = true;
                html += `
                    <h4 style="margin-top: 20px; margin-bottom: 10px; font-size: 16px;">Lambda Function Notifications</h4>
                    <table style="width: 100%; margin-bottom: 20px;">
                        <thead>
                            <tr>
                                <th>Function ARN</th>
                                <th>Events</th>
                                <th>Filter</th>
                            </tr>
                        </thead>
                        <tbody>`;

                for (const config of notificationConfig.LambdaFunctionConfigurations) {
                    const functionArn = config.LambdaFunctionArn || 'N/A';
                    const functionName = functionArn.split(':').pop();
                    const events = config.Events ? config.Events.join(', ') : 'None';
                    const filter = config.Filter?.Key?.FilterRules?.[0] ?
                        `${config.Filter.Key.FilterRules[0].Name}: ${config.Filter.Key.FilterRules[0].Value}` :
                        'All objects';

                    html += `
                        <tr>
                            <td>
                                <div><strong>${functionName}</strong></div>
                                <div style="font-size: 11px; color: #545B64; margin-top: 4px;"><code>${functionArn}</code></div>
                            </td>
                            <td style="font-size: 13px;">${events}</td>
                            <td style="font-size: 13px;">${filter}</td>
                        </tr>
                    `;
                }

                html += `</tbody></table>`;
            }

            // SNS Topic Configurations
            // if (notificationConfig.TopicConfigurations && notificationConfig.TopicConfigurations.length > 0) {
            //     hasNotifications = true;
            //     html += `
            //         <h4 style="margin-top: 20px; margin-bottom: 10px; font-size: 16px;">SNS Topic Notifications</h4>
            //         <table style="width: 100%; margin-bottom: 20px;">
            //             <thead>
            //                 <tr>
            //                     <th>Topic ARN</th>
            //                     <th>Events</th>
            //                     <th>Filter</th>
            //                 </tr>
            //             </thead>
            //             <tbody>`;

            //     for (const config of notificationConfig.TopicConfigurations) {
            //         const topicArn = config.TopicArn || 'N/A';
            //         const topicName = topicArn.split(':').pop();
            //         const events = config.Events ? config.Events.join(', ') : 'None';
            //         const filter = config.Filter?.Key?.FilterRules?.[0] ?
            //             `${config.Filter.Key.FilterRules[0].Name}: ${config.Filter.Key.FilterRules[0].Value}` :
            //             'All objects';

            //         html += `
            //             <tr>
            //                 <td>
            //                     <div><strong>${topicName}</strong></div>
            //                     <div style="font-size: 11px; color: #545B64; margin-top: 4px;"><code>${topicArn}</code></div>
            //                 </td>
            //                 <td style="font-size: 13px;">${events}</td>
            //                 <td style="font-size: 13px;">${filter}</td>
            //             </tr>
            //         `;
            //     }

            //     html += `</tbody></table>`;
            // }
        }

        if (!hasNotifications) {
            html += `<p style="color: var(--text-primary); font-style: italic;">No event notifications configured</p>`;
        }

        content.innerHTML = html;

    } catch (error) {
        console.error('Error loading bucket details:', error);
        const content = document.getElementById('bucket-details-content');
        content.innerHTML = `<p style="color: var(--danger);">Error loading bucket details: ${error.message}</p>`;
    }
}

async function deleteNotification(bucketName, notificationId) {
    showConfirmModal(
        `Are you sure you want to delete notification: ${notificationId}?`,
        async () => {
            try {
                const response = await fetch(`${API_BASE}s3/buckets/${bucketName}/notification/${notificationId}`, {
                    method: 'DELETE'
                });

                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.message || 'Failed to delete notification');
                }

                showNotification('Event notification deleted successfully', 'success');

                // Refresh bucket details
                viewBucketDetails(bucketName);
            } catch (error) {
                console.error('Error deleting notification:', error);
                showNotification('Error deleting notification: ' + error.message, 'error');
            }
        }
    );
}

// delete function:
async function deleteLifecycleRule(bucketName, ruleId) {
    showConfirmModal(
        `Are you sure you want to delete lifecycle rule: ${ruleId}?`,
        async () => {
            try {
                const response = await fetch(`${API_BASE}s3/buckets/${bucketName}/lifecycle/${ruleId}`, {
                    method: 'DELETE'
                });

                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.message || 'Failed to delete lifecycle rule');
                }

                showNotification('Lifecycle rule deleted successfully', 'success');
                viewBucketDetails(bucketName);
            } catch (error) {
                console.error('Error deleting lifecycle rule:', error);
                showNotification('Error deleting lifecycle rule: ' + error.message, 'error');
            }
        }
    );
}

async function loadBuckets() {
    const loading = document.getElementById('s3-loading');
    const content = document.getElementById('s3-content');
    const empty = document.getElementById('s3-empty');

    loading.style.display = 'block';
    content.style.display = 'none';
    empty.style.display = 'none';

    try {
        // Simple proxy request through Flask API (like SQS/Lambda)
        const response = await fetch(`${API_BASE}s3/buckets`, {
            method: 'GET'
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${await response.text()}`);
        }

        const data = await response.json();
        const buckets = data.Buckets || [];

        if (buckets.length === 0) {
            loading.style.display = 'none';
            empty.style.display = 'block';
            updateS3Stats(0, 0);
            return;
        }

        const tbody = document.querySelector('#s3-table tbody');
        tbody.innerHTML = '';

        for (const bucket of buckets) {
            const row = tbody.insertRow();
            const createdDate = bucket.CreationDate ? new Date(bucket.CreationDate).toLocaleString() : 'N/A';

            row.innerHTML = `
                <td><strong>${bucket.Name}</strong></td>
                <td>${S3_CONFIG.region}</td>
                <td>${createdDate}</td>
                <td>
                    <div class="action-buttons">
                        <button class="btn btn-secondary" onclick="viewBucketDetails('${bucket.Name}')">Details</button>
                        <button class="btn btn-secondary" onclick="viewBucketObjects('${bucket.Name}')">View Objects</button>
                        <button class="btn btn-danger" onclick="deleteBucket('${bucket.Name}')">Delete</button>
                    </div>
                </td>
            `;
        }

        updateS3Stats(buckets.length, 0);

        loading.style.display = 'none';
        content.style.display = 'block';

    } catch (error) {
        console.error('Error loading buckets:', error);
        loading.innerHTML = `<p style="color: var(--danger);">Error loading buckets: ${error.message}</p>`;
    }
}

function updateS3Stats(bucketCount, objectCount) {
    const statsDiv = document.getElementById('s3-stats');
    statsDiv.innerHTML = `
        <div class="stat-card">
            <div class="stat-label">Total Buckets</div>
            <div class="stat-value">${bucketCount}</div>
        </div>
    `;
}

function showCreateBucketModal() {
    document.getElementById('bucket-name').value = '';
    showModal('create-bucket-modal');
}

async function createBucket(event) {
    event.preventDefault();

    const bucketName = document.getElementById('bucket-name').value;

    try {
        const response = await fetch(`${API_BASE}s3/buckets`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ bucketName })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.message || 'Failed to create bucket');
        }

        closeModal('create-bucket-modal');
        showNotification(`Bucket ${bucketName} created successfully`, 'success');
        loadBuckets();
    } catch (error) {
        console.error('Error creating bucket:', error);
        showNotification('Error creating bucket: ' + error.message, 'error');
    }
}

async function viewBucketObjects(bucketName, prefix = '') {
    currentBucket = bucketName;
    currentPrefix = prefix;

    try {
        const url = `${API_BASE}s3/buckets/${bucketName}/objects${prefix ? '?prefix=' + encodeURIComponent(prefix) : ''}`;
        const response = await fetch(url);

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${await response.text()}`);
        }

        const data = await response.json();

        const objects = data.Contents || [];
        const prefixes = data.CommonPrefixes || [];

        document.getElementById('bucket-objects-name').textContent = bucketName;
        renderBreadcrumb(bucketName, prefix);
        renderObjects(objects, prefixes);

        showModal('bucket-objects-modal');
    } catch (error) {
        console.error('Error loading bucket objects:', error);
        showNotification('Error loading bucket objects: ' + error.message, 'error');
    }
}

function renderBreadcrumb(bucketName, prefix) {
    const breadcrumb = document.getElementById('s3-breadcrumb');
    let html = `<a onclick="viewBucketObjects('${bucketName}')">${bucketName}</a>`;

    if (prefix) {
        const parts = prefix.split('/').filter(p => p);
        let currentPath = '';

        for (let i = 0; i < parts.length; i++) {
            currentPath += parts[i] + '/';
            html += ` <span class="breadcrumb-separator">/</span> `;
            html += `<a onclick="viewBucketObjects('${bucketName}', '${currentPath}')">${parts[i]}</a>`;
        }
    }

    breadcrumb.innerHTML = html;
}

function renderObjects(objects, prefixes) {
    const content = document.getElementById('bucket-objects-content');

    if (objects.length === 0 && prefixes.length === 0) {
        content.innerHTML = '<p>No objects found in this location.</p>';
        return;
    }

    let html = '<div style="display: flex; flex-direction: column; gap: 8px;">';

    // Render folders
    for (const prefix of prefixes) {
        const folderName = prefix.Prefix.substring(currentPrefix.length).replace(/\/$/, '');
        html += `
            <div style="display: flex; align-items: center; padding: 12px; border-radius: 4px; gap: 12px;">
                <div style="flex: 1; cursor: pointer;" onclick="viewBucketObjects('${currentBucket}', '${prefix.Prefix}')">
                    <span style="color: var(--aws-blue); font-size: 20px;">📁</span>
                    <strong style="margin-left: 8px;">${folderName}</strong>
                </div>
            </div>
        `;
    }

    // Render files
    for (const obj of objects) {
        const fileName = obj.Key.substring(currentPrefix.length);
        if (!fileName) continue;

        const sizeMB = (obj.Size / 1024 / 1024).toFixed(2);
        const sizeDisplay = obj.Size < 1024 ? `${obj.Size} B` :
            obj.Size < 1024 * 1024 ? `${(obj.Size / 1024).toFixed(2)} KB` :
                `${sizeMB} MB`;
        const modifiedDate = obj.LastModified ? new Date(obj.LastModified).toLocaleString() : 'N/A';

        html += `
            <div style="display: flex; align-items: center; padding: 12px; border: 1px solid var(--border-light) border-radius: 4px; gap: 12px;">
                <span style="font-size: 20px;">📄</span>
                <div style="flex: 1; min-width: 0;">
                    <div style="font-weight: 500; overflow: hidden; text-overflow: ellipsis;">${fileName}</div>
                    <div style="font-size: 12px; color: var(--text-primary); margin-top: 4px;">
                        ${sizeDisplay} • ${modifiedDate}
                    </div>
                </div>
                <div style="display: flex; gap: 8px; flex-shrink: 0;">
                    <button class="btn btn-secondary" onclick="viewObjectMetadata('${currentBucket}', '${obj.Key}')" title="Info">
                        ℹ️
                    </button>
                    <button class="btn btn-secondary" onclick="downloadObject('${currentBucket}', '${obj.Key}')" title="Download">
                        ⬇️
                    </button>
                    <button class="btn btn-secondary" onclick="showRenameObjectModal('${obj.Key}')" title="Rename">
                        ✏️
                    </button>
                    <button class="btn btn-secondary" onclick="showMoveObjectModal('${obj.Key}')" title="Move">
                        ➡️
                    </button>
                    <button class="btn btn-danger" onclick="deleteObject('${currentBucket}', '${obj.Key}')" title="Delete">
                        🗑️
                    </button>
                </div>
            </div>
        `;
    }

    html += '</div>';
    content.innerHTML = html;
}

function filterS3Objects() {
    const filter = document.getElementById('s3-prefix-filter').value;
    viewBucketObjects(currentBucket, filter);
}

function showUploadObjectModal() {
    document.getElementById('upload-file').value = '';
    document.getElementById('upload-key').value = currentPrefix;
    showModal('upload-object-modal');
}

async function uploadObject(event) {
    event.preventDefault();

    const file = document.getElementById('upload-file').files[0];
    const key = document.getElementById('upload-key').value;

    if (!file) {
        showNotification('Please select a file', 'error');
        return;
    }

    try {
        const formData = new FormData();
        formData.append('bucketName', currentBucket);
        formData.append('key', key);
        formData.append('file', file);

        const response = await fetch(`${API_BASE}s3/buckets/${currentBucket}/objects`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error('Failed to upload object');
        }

        closeModal('upload-object-modal');
        showNotification('File uploaded successfully', 'success');
        viewBucketObjects(currentBucket, currentPrefix);
    } catch (error) {
        console.error('Error uploading object:', error);
        showNotification('Error uploading object: ' + error.message, 'error');
    }
}

async function downloadObject(bucketName, key) {
    try {
        const response = await fetch(`${API_BASE}s3/buckets/${bucketName}/objects/${key}`);

        if (!response.ok) {
            throw new Error('Failed to download object');
        }

        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = key.split('/').pop();
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    } catch (error) {
        console.error('Error downloading object:', error);
        showNotification('Error downloading object: ' + error.message, 'error');
    }
}

function showRenameObjectModal(key) {
    document.getElementById('rename-old-key').value = key;
    document.getElementById('rename-new-key').value = key;
    showModal('rename-object-modal');
}

async function viewObjectMetadata(bucketName, key) {
    try {
        const response = await fetch(`${API_BASE}s3/buckets/${bucketName}/objects/${key}/metadata`);

        if (!response.ok) {
            throw new Error('Failed to load object metadata');
        }

        const metadata = await response.json();

        const content = document.getElementById('object-metadata-content');

        const sizeMB = (metadata.Size / 1024 / 1024).toFixed(2);
        const sizeDisplay = metadata.Size < 1024 ? `${metadata.Size} B` :
            metadata.Size < 1024 * 1024 ? `${(metadata.Size / 1024).toFixed(2)} KB` :
                `${sizeMB} MB`;

        content.innerHTML = `
            <div class="detail-row">
                <div class="detail-label">Object Key</div>
                <div class="detail-value"><code>${metadata.Key}</code></div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Bucket</div>
                <div class="detail-value"><code>${metadata.Bucket}</code></div>
            </div>
            <div class="detail-row">
                <div class="detail-label">ARN</div>
                <div class="detail-value"><code>${metadata.ARN}</code></div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Object URL</div>
                <div class="detail-value">
                    <code style="word-break: break-all;">${metadata.ObjectUrl}</code>
                    <button class="btn btn-secondary" style="margin-left: 10px;" onclick="copyToClipboard('${metadata.ObjectUrl}')">Copy</button>
                </div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Size</div>
                <div class="detail-value">${sizeDisplay} (${metadata.Size.toLocaleString()} bytes)</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Last Modified</div>
                <div class="detail-value">${metadata.LastModified ? new Date(metadata.LastModified).toLocaleString() : 'N/A'}</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">ETag</div>
                <div class="detail-value"><code>${metadata.ETag || 'N/A'}</code></div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Content Type</div>
                <div class="detail-value">${metadata.ContentType}</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Storage Class</div>
                <div class="detail-value">${metadata.StorageClass}</div>
            </div>
            ${metadata.ServerSideEncryption ? `
            <div class="detail-row">
                <div class="detail-label">Encryption</div>
                <div class="detail-value">${metadata.ServerSideEncryption}</div>
            </div>
            ` : ''}
            ${metadata.VersionId ? `
            <div class="detail-row">
                <div class="detail-label">Version ID</div>
                <div class="detail-value"><code>${metadata.VersionId}</code></div>
            </div>
            ` : ''}
            ${Object.keys(metadata.Metadata).length > 0 ? `
            <div class="detail-row">
                <div class="detail-label">Custom Metadata</div>
                <div class="detail-value"><pre class="code-block">${JSON.stringify(metadata.Metadata, null, 2)}</pre></div>
            </div>
            ` : ''}
        `;

        showModal('object-metadata-modal');
    } catch (error) {
        console.error('Error loading object metadata:', error);
        showNotification(`Error loading metadata: ${error.message}`, 'error');
    }
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showNotification('URL copied to clipboard', 'success');
    }).catch(err => {
        showNotification('Failed to copy to clipboard', 'error');
    });
}

async function renameObject(event) {
    event.preventDefault();

    const oldKey = document.getElementById('rename-old-key').value;
    const newKey = document.getElementById('rename-new-key').value;

    if (oldKey === newKey) {
        showNotification('New key must be different from old key', 'error');
        return;
    }

    try {
        const response = await fetch(`${API_BASE}s3/buckets/${currentBucket}/objects/copy`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                sourceKey: oldKey,
                destBucket: currentBucket,
                destKey: newKey,
                deleteSource: true
            })
        });

        if (!response.ok) {
            throw new Error('Failed to rename object');
        }

        closeModal('rename-object-modal');
        showNotification('Object renamed successfully', 'success');
        viewBucketObjects(currentBucket, currentPrefix);
    } catch (error) {
        console.error('Error renaming object:', error);
        showNotification('Error renaming object: ' + error.message, 'error');
    }
}

function showMoveObjectModal(key) {
    document.getElementById('move-old-key').value = key;
    document.getElementById('move-dest-bucket').value = '';
    document.getElementById('move-dest-key').value = key;
    showModal('move-object-modal');
}

async function moveObject(event) {
    event.preventDefault();

    const oldKey = document.getElementById('move-old-key').value;
    const destBucket = document.getElementById('move-dest-bucket').value;
    const destKey = document.getElementById('move-dest-key').value;

    try {
        const response = await fetch(`${API_BASE}s3/buckets/${currentBucket}/objects/copy`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                sourceKey: oldKey,
                destBucket: destBucket,
                destKey: destKey,
                deleteSource: true
            })
        });

        if (!response.ok) {
            throw new Error('Failed to move object');
        }

        closeModal('move-object-modal');
        showNotification('Object moved successfully', 'success');
        viewBucketObjects(currentBucket, currentPrefix);
    } catch (error) {
        console.error('Error moving object:', error);
        showNotification('Error moving object: ' + error.message, 'error');
    }
}

async function deleteObject(bucketName, key) {
    showConfirmModal(
        `Are you sure you want to delete: ${key}?`,
        async () => {
            try {
                const response = await fetch(`${API_BASE}s3/buckets/${bucketName}/objects/${key}`, {
                    method: 'DELETE'
                });

                if (!response.ok) {
                    throw new Error('Failed to delete object');
                }

                showNotification('Object deleted successfully', 'success');
                viewBucketObjects(bucketName, currentPrefix);
            } catch (error) {
                console.error('Error deleting object:', error);
                showNotification('Error deleting object: ' + error.message, 'error');
            }
        }
    )
}

async function deleteBucket(bucketName) {
    showConfirmModal(
        `Are you sure you want to delete bucket <strong>${bucketName}</strong>?<br><br>
        If the bucket contains objects, they will be deleted as well.<br>
        <strong>This cannot be undone.</strong>`,
        async () => {
            try {
                const response = await fetch(`${API_BASE}s3/buckets/${bucketName}?force=true`, {
                    method: 'DELETE'
                });

                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.message || 'Failed to delete bucket');
                }

                showNotification(`Bucket ${bucketName} deleted successfully`, 'success');
                loadBuckets();
            } catch (error) {
                console.error('Error deleting bucket:', error);
                showNotification(`Error deleting bucket: ${error.message}`, 'error');
            }
        }
    );
}

function sortByProperty(property, order = 'asc') {
    return function (a, b) {
        const valueA = typeof a[property] === 'string' ? a[property].toUpperCase() : a[property];
        const valueB = typeof b[property] === 'string' ? b[property].toUpperCase() : b[property];

        let comparison = 0;
        if (valueA > valueB) {
            comparison = 1;
        } else if (valueA < valueB) {
            comparison = -1;
        }

        // Apply descending order logic if requested
        return order === 'desc' ? comparison * -1 : comparison;
    };
}


// Load all secrets
async function loadSecrets() {
    const loading = document.getElementById('secretsmanager-loading');
    const content = document.getElementById('secretsmanager-content');
    const empty = document.getElementById('secretsmanager-empty');
    const tbody = document.querySelector('#secretsmanager-table tbody');
    const showDeleted = document.getElementById('show-deleted-secrets').checked;

    // Save checkbox state to localStorage
    localStorage.setItem('showDeletedSecrets', showDeleted);

    loading.style.display = 'block';
    content.style.display = 'none';
    empty.style.display = 'none';

    try {
        const response = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Target': 'secretsmanager.ListSecrets'
            },
            body: JSON.stringify({
                MaxResults: 100
            })
        });

        const data = await response.json();

        loading.style.display = 'none';

        if (!data.SecretList || data.SecretList.length === 0) {
            empty.style.display = 'block';
            updateSecretsStats(0, 0);
            return;
        }

        // Filter secrets based on checkbox
        const filteredSecrets = showDeleted
            ? data.SecretList
            : data.SecretList.filter(s => !s.DeletedDate);

        if (filteredSecrets.length === 0) {
            empty.style.display = 'block';
            updateSecretsStats(data.SecretList.length, data.SecretList.filter(s => s.DeletedDate).length);
            return;
        }

        tbody.innerHTML = '';
        filteredSecrets.forEach(secret => {
            const row = tbody.insertRow();
            const isDeleted = !!secret.DeletedDate;

            // Apply styling for deleted secrets
            if (isDeleted) {
                row.style.backgroundColor = 'var(--bg-tertiary)';
                row.style.opacity = '0.7';
            }

            // Secret Name
            const nameCell = row.insertCell();
            nameCell.textContent = secret.Name;

            // Description
            const descCell = row.insertCell();
            descCell.textContent = secret.Description || '-';

            // Last Modified
            const modifiedCell = row.insertCell();
            modifiedCell.textContent = new Date(secret.LastChangedDate * 1000).toLocaleString();

            // Status
            const statusCell = row.insertCell();
            if (isDeleted) {
                const deletionDate = new Date(secret.DeletedDate * 1000);
                const daysRemaining = Math.ceil((secret.DeletedDate - Date.now() / 1000) / 86400);
                statusCell.innerHTML = `<span style="color: var(--danger); font-weight: 500;">Scheduled for deletion</span><br><small style="color: var(--text-secondary);">Deletes on ${deletionDate.toLocaleDateString()} (${daysRemaining} days)</small>`;
            } else {
                statusCell.innerHTML = `<span style="color: var(--success); font-weight: 500;">Active</span>`;
            }

            // Actions
            const actionsCell = row.insertCell();
            if (isDeleted) {
                actionsCell.innerHTML = `
                    <div class="action-buttons">
                        <button class="btn btn-primary" onclick="showRestoreSecretModal('${secret.Name}')">Restore</button>
                    </div>
                `;
            } else {
                actionsCell.innerHTML = `
                    <div class="action-buttons">
                        <button class="btn btn-primary" onclick="viewSecret('${secret.Name}')">View</button>
                        <button class="btn btn-warning" onclick="showUpdateSecretModal('${secret.Name}')">Update</button>
                        <button class="btn btn-danger" onclick="showDeleteSecretModal('${secret.Name}')">Delete</button>
                    </div>
                `;
            }
        });

        content.style.display = 'block';
        updateSecretsStats(data.SecretList.length, data.SecretList.filter(s => s.DeletedDate).length);

    } catch (error) {
        console.error('Error loading secrets:', error);
        loading.style.display = 'none';
        empty.style.display = 'block';
        showNotification('Failed to load secrets: ' + error.message, 'error');
    }
}

// Update secrets statistics
function updateSecretsStats(total, deleted) {
    const statsDiv = document.getElementById('secretsmanager-stats');
    const active = total - deleted;
    statsDiv.innerHTML = `
        <div class="stat-card">
            <div class="stat-label">Total Secrets</div>
            <div class="stat-value">${total}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Active</div>
            <div class="stat-value">${active}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Scheduled for Deletion</div>
            <div class="stat-value">${deleted}</div>
        </div>
    `;
}

// Show restore secret modal
function showRestoreSecretModal(secretName) {
    document.getElementById('restore-secret-name').value = secretName;
    document.getElementById('restore-secret-display-name').textContent = secretName;
    showModal('restore-secret-modal');
}

// Confirm restore secret
async function confirmRestoreSecret(event) {
    event.preventDefault();

    const secretName = document.getElementById('restore-secret-name').value;

    try {
        const response = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Target': 'secretsmanager.RestoreSecret'
            },
            body: JSON.stringify({
                SecretId: secretName
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || 'Failed to restore secret');
        }

        // Close modal
        closeModal('restore-secret-modal');

        showNotification(`Secret "${secretName}" has been restored successfully`, 'success');

        // Reload the secrets list
        loadSecrets();

    } catch (error) {
        console.error('Error restoring secret:', error);
        showNotification('Failed to restore secret: ' + error.message, 'error');
    }
}

// Show create secret modal
function showCreateSecretModal() {
    document.getElementById('secret-name').value = '';
    document.getElementById('secret-description').value = '';
    document.getElementById('secret-string').value = '';
    document.getElementById('secret-binary').value = '';
    document.getElementById('secret-type').value = 'string';
    toggleSecretType();
    showModal('create-secret-modal');
}

// Toggle between string and binary secret types
function toggleSecretType() {
    const type = document.getElementById('secret-type').value;
    const stringGroup = document.getElementById('secret-string-group');
    const binaryGroup = document.getElementById('secret-binary-group');

    if (type === 'string') {
        stringGroup.style.display = 'block';
        binaryGroup.style.display = 'none';
        document.getElementById('secret-string').required = true;
        document.getElementById('secret-binary').required = false;
    } else {
        stringGroup.style.display = 'none';
        binaryGroup.style.display = 'block';
        document.getElementById('secret-string').required = false;
        document.getElementById('secret-binary').required = true;
    }
}

// Toggle update secret type
function toggleUpdateSecretType() {
    const type = document.getElementById('update-secret-type').value;
    const stringGroup = document.getElementById('update-secret-string-group');
    const binaryGroup = document.getElementById('update-secret-binary-group');

    if (type === 'string') {
        stringGroup.style.display = 'block';
        binaryGroup.style.display = 'none';
        document.getElementById('update-secret-string').required = true;
        document.getElementById('update-secret-binary').required = false;
    } else {
        stringGroup.style.display = 'none';
        binaryGroup.style.display = 'block';
        document.getElementById('update-secret-string').required = false;
        document.getElementById('update-secret-binary').required = true;
    }
}

// Create new secret
async function createSecret(event) {
    event.preventDefault();

    const name = document.getElementById('secret-name').value;
    const description = document.getElementById('secret-description').value;
    const type = document.getElementById('secret-type').value;

    const payload = {
        Name: name
    };

    // Only add description if it has a value
    if (description) {
        payload.Description = description;
    }

    // Add the secret value based on type
    if (type === 'string') {
        const secretString = document.getElementById('secret-string').value;
        if (!secretString) {
            showNotification('Secret value is required', 'error');
            return;
        }
        payload.SecretString = secretString;
    } else {
        const secretBinary = document.getElementById('secret-binary').value;
        if (!secretBinary) {
            showNotification('Secret binary value is required', 'error');
            return;
        }
        payload.SecretBinary = secretBinary;
    }

    try {
        const response = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Target': 'secretsmanager.CreateSecret'
            },
            body: JSON.stringify(payload)
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || 'Failed to create secret');
        }

        showNotification(
            `Secret "${name}" created successfully with version ${data.VersionId}...`,
            'success'
        );
        closeModal('create-secret-modal');
        loadSecrets();

    } catch (error) {
        console.error('Error creating secret:', error);
        showNotification('Failed to create secret: ' + error.message, 'error');
    }
}

// View secret details
async function viewSecret(secretName) {
    currentSecretName = secretName;

    try {
        const response = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Target': 'secretsmanager.DescribeSecret'
            },
            body: JSON.stringify({
                SecretId: secretName
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || 'Failed to describe secret');
        }

        // Populate modal with secret details
        document.getElementById('view-secret-name').textContent = data.Name;
        document.getElementById('view-secret-arn').textContent = data.ARN;
        document.getElementById('view-secret-description').textContent = data.Description || '-';
        document.getElementById('view-secret-created').textContent = new Date(data.CreatedDate * 1000).toLocaleString();
        document.getElementById('view-secret-modified').textContent = new Date(data.LastChangedDate * 1000).toLocaleString();
        document.getElementById('view-secret-accessed').textContent = data.LastAccessedDate
            ? new Date(data.LastAccessedDate * 1000).toLocaleString()
            : '-';

        // Display version information
        const versionStages = data.VersionIdsToStages || {};
        const currentVersionId = Object.keys(versionStages).find(vid =>
            versionStages[vid].includes('AWSCURRENT')
        );

        document.getElementById('view-secret-version').textContent = currentVersionId || '-';

        // Load all versions for the version selector
        await loadSecretVersions(secretName, currentVersionId, versionStages);

        // Hide secret value section initially
        document.getElementById('secret-value-section').style.display = 'none';
        document.getElementById('restore-version-btn').style.display = 'none';
        document.getElementById('version-info-banner').style.display = 'none';

        showModal('view-secret-modal');
    } catch (error) {
        console.error('Error viewing secret:', error);
        showNotification('Failed to view secret: ' + error.message, 'error');
    }
}

// Load all secret versions into the version selector
async function loadSecretVersions(secretName, currentVersionId, versionStages) {
    const selector = document.getElementById('version-selector');

    try {
        // Get list of all versions
        const response = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Target': 'secretsmanager.ListSecretVersionIds'
            },
            body: JSON.stringify({
                SecretId: secretName,
                IncludeDeprecated: true
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || 'Failed to list versions');
        }

        // Clear and populate selector
        selector.innerHTML = '';

        if (data.Versions && data.Versions.length > 0) {
            data.Versions.forEach(version => {
                const option = document.createElement('option');
                option.value = version.VersionId;

                // Build label with stages
                const stages = version.VersionStages || [];
                let label = version.VersionId;

                if (stages.length > 0) {
                    label += ` (${stages.join(', ')})`;

                    // Mark current version
                    if (stages.includes('AWSCURRENT')) {
                        label += ' ← CURRENT';
                        option.selected = true;
                    } else if (stages.includes('AWSPREVIOUS')) {
                        label += ' ← PREVIOUS';
                    }
                } else {
                    label += ' (deprecated)';
                }

                // Add timestamp
                const created = new Date(version.CreatedDate * 1000);
                label += ` - ${created.toLocaleDateString()} ${created.toLocaleTimeString()}`;

                option.textContent = label;
                option.dataset.stages = JSON.stringify(stages);
                option.dataset.isCurrent = stages.includes('AWSCURRENT') ? 'true' : 'false';

                selector.appendChild(option);
            });
        } else {
            const option = document.createElement('option');
            option.value = '';
            option.textContent = 'No versions found';
            selector.appendChild(option);
        }

    } catch (error) {
        console.error('Error loading versions:', error);
        selector.innerHTML = '<option value="">Error loading versions</option>';
    }
}

// Handle version selector change
function onVersionChange() {
    // Hide secret value when version changes
    document.getElementById('secret-value-section').style.display = 'none';

    // Show/hide restore button based on whether current version is selected
    const selector = document.getElementById('version-selector');
    const selectedOption = selector.options[selector.selectedIndex];

    if (selectedOption && selectedOption.dataset.isCurrent === 'false') {
        document.getElementById('restore-version-btn').style.display = 'inline-block';
    } else {
        document.getElementById('restore-version-btn').style.display = 'none';
    }
}

// Restore selected version to current
async function restoreSelectedVersion() {
    if (!currentSecretName) return;

    const selector = document.getElementById('version-selector');
    const versionId = selector.value;

    if (!versionId) {
        showNotification('Please select a version to restore', 'warning');
        return;
    }

    const selectedOption = selector.options[selector.selectedIndex];
    const isCurrent = selectedOption.dataset.isCurrent === 'true';

    if (isCurrent) {
        showNotification('This version is already current', 'info');
        return;
    }

    showConfirmModal(
        'Restore Version</br>' +
        `Are you sure you want to restore this version?</br></br>` +
        `<strong>Version:</strong> ${versionId}...</br></br>` +
        `This will:</br>` +
        `• Retrieve the old version's value</br>` +
        `• Create a new version with that value</br>` +
        `• Make the new version AWSCURRENT</br>` +
        `• Move the old AWSCURRENT to AWSPREVIOUS`,
        async () => {
            try {
                // First, get the value of the version we want to restore
                const getResponse = await fetch(API_BASE, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-amz-json-1.1',
                        'X-Amz-Target': 'secretsmanager.GetSecretValue'
                    },
                    body: JSON.stringify({
                        SecretId: currentSecretName,
                        VersionId: versionId
                    })
                });

                const getValue = await getResponse.json();

                if (!getResponse.ok) {
                    throw new Error(getValue.message || 'Failed to retrieve version value');
                }

                // Then create a new version with that value (makes it AWSCURRENT)
                const putBody = {
                    SecretId: currentSecretName,
                    VersionStages: ['AWSCURRENT']
                };

                if (getValue.SecretString) {
                    putBody.SecretString = getValue.SecretString;
                } else if (getValue.SecretBinary) {
                    putBody.SecretBinary = getValue.SecretBinary;
                }

                const putResponse = await fetch(API_BASE, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-amz-json-1.1',
                        'X-Amz-Target': 'secretsmanager.PutSecretValue'
                    },
                    body: JSON.stringify(putBody)
                });

                const putData = await putResponse.json();

                if (!putResponse.ok) {
                    throw new Error(putData.message || 'Failed to restore version');
                }

                showNotification('Version restored successfully! A new version has been created as AWSCURRENT.', 'success');

                // Refresh the modal to show updated versions
                closeModal('view-secret-modal');
                await viewSecret(currentSecretName);

            } catch (error) {
                console.error('Error restoring version:', error);
                showNotification('Failed to restore version: ' + error.message, 'error');
            }
        }
    );
}

// Retrieve secret value
async function retrieveSecretValue() {
    if (!currentSecretName) return;

    const selector = document.getElementById('version-selector');
    const selectedVersionId = selector.value;

    if (!selectedVersionId) {
        showNotification('Please select a version', 'warning');
        return;
    }

    const selectedOption = selector.options[selector.selectedIndex];
    const isCurrent = selectedOption.dataset.isCurrent === 'true';

    try {
        const requestBody = {
            SecretId: currentSecretName
        };

        // Only add VersionId if not current (AWS defaults to AWSCURRENT)
        if (selectedVersionId) {
            requestBody.VersionId = selectedVersionId;
        }

        const response = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Target': 'secretsmanager.GetSecretValue'
            },
            body: JSON.stringify(requestBody)
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || 'Failed to retrieve secret value');
        }

        const valueSection = document.getElementById('secret-value-section');
        const valueElement = document.getElementById('view-secret-value');
        const versionBanner = document.getElementById('version-info-banner');

        if (data.SecretString) {
            // Try to format as JSON if possible
            try {
                const jsonValue = JSON.parse(data.SecretString);
                valueElement.textContent = JSON.stringify(jsonValue, null, 2);
            } catch (e) {
                // Not JSON, display as plain text
                valueElement.textContent = data.SecretString;
            }
        } else if (data.SecretBinary) {
            valueElement.textContent = `[Binary Data - Base64]\n${data.SecretBinary}`;
        } else {
            valueElement.textContent = '[No value]';
        }

        // Show warning banner if viewing a previous version
        if (!isCurrent) {
            versionBanner.style.display = 'block';
        } else {
            versionBanner.style.display = 'none';
        }

        valueSection.style.display = 'block';

    } catch (error) {
        console.error('Error retrieving secret value:', error);
        showNotification('Failed to retrieve secret value: ' + error.message, 'error');
    }
}

// Show update secret modal
async function showUpdateSecretModal(secretName) {
    document.getElementById('update-secret-name').value = secretName;

    try {
        // Get current secret details AND value to determine type
        const describeResponse = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Target': 'secretsmanager.DescribeSecret'
            },
            body: JSON.stringify({
                SecretId: secretName
            })
        });

        const describeData = await describeResponse.json();

        if (!describeResponse.ok) {
            throw new Error(describeData.message || 'Failed to describe secret');
        }

        // Get the actual secret value to determine if it's binary or string
        const valueResponse = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Target': 'secretsmanager.GetSecretValue'
            },
            body: JSON.stringify({
                SecretId: secretName
            })
        });

        const valueData = await valueResponse.json();

        if (!valueResponse.ok) {
            throw new Error(valueData.message || 'Failed to retrieve secret value');
        }

        // Check if this is a binary secret
        const isBinary = !!valueData.SecretBinary;

        if (isBinary) {
            // AWS Console doesn't allow updating binary secrets
            showNotification('Binary secrets cannot be updated through the console. Please use the AWS CLI or SDK.', 'warning');
            return;
        }

        // It's a string secret - populate the form
        document.getElementById('update-secret-description').value = describeData.Description || '';
        document.getElementById('update-secret-string').value = '';

        // Remove the type selector entirely - secret type is fixed
        const typeGroup = document.getElementById('update-secret-type-group');
        if (typeGroup) {
            typeGroup.style.display = 'none';
        }

        // Only show string input, hide binary
        document.getElementById('update-secret-string-group').style.display = 'block';
        document.getElementById('update-secret-binary-group').style.display = 'none';

        // Store the secret type in a hidden field
        document.getElementById('update-secret-type-hidden').value = 'string';

        showModal('update-secret-modal');

    } catch (error) {
        console.error('Error loading secret for update:', error);
        showNotification('Failed to load secret: ' + error.message, 'error');
    }
}

// Update secret
async function updateSecret(event) {
    event.preventDefault();

    const name = document.getElementById('update-secret-name').value;
    const description = document.getElementById('update-secret-description').value;

    // Secret type is fixed - can only be string at this point since binary is blocked
    const secretString = document.getElementById('update-secret-string').value;
    if (!secretString) {
        showNotification('Secret value is required', 'error');
        return;
    }

    const payload = {
        SecretId: name,
        SecretString: secretString
    };

    // Only update description if it was changed
    if (description) {
        payload.Description = description;
    }

    try {
        const response = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Target': 'secretsmanager.UpdateSecret'
            },
            body: JSON.stringify(payload)
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || 'Failed to update secret');
        }

        showNotification(`Secret "${name}" updated successfully with new version ${data.VersionId}`, 'success');
        closeModal('update-secret-modal');
        loadSecrets();

    } catch (error) {
        console.error('Error updating secret:', error);
        showNotification('Failed to update secret: ' + error.message, 'error');
    }
}

// Delete secret
// Show delete secret modal - NEW FUNCTION
function showDeleteSecretModal(secretName) {
    // Populate the modal
    document.getElementById('delete-secret-name').value = secretName;
    document.getElementById('delete-secret-display-name').textContent = secretName;

    // Reset form to defaults
    document.getElementById('delete-recovery-days').value = 30;
    document.getElementById('delete-force-immediate').checked = false;
    document.getElementById('delete-recovery-days').disabled = false;
    document.getElementById('immediate-delete-warning').style.display = 'none';
    document.getElementById('delete-confirm-button').textContent = 'Schedule deletion';

    showModal('delete-secret-modal');
}

// Toggle immediate delete warning - NEW FUNCTION
function toggleImmediateDelete() {
    const forceImmediate = document.getElementById('delete-force-immediate').checked;
    const recoveryDaysInput = document.getElementById('delete-recovery-days');
    const warningDiv = document.getElementById('immediate-delete-warning');
    const confirmButton = document.getElementById('delete-confirm-button');

    if (forceImmediate) {
        // Immediate deletion mode
        recoveryDaysInput.disabled = true;
        recoveryDaysInput.style.opacity = '0.5';
        warningDiv.style.display = 'block';
        confirmButton.textContent = 'Delete immediately';
        confirmButton.style.background = '#8B0000'; // Darker red for emphasis
    } else {
        // Scheduled deletion mode
        recoveryDaysInput.disabled = false;
        recoveryDaysInput.style.opacity = '1';
        warningDiv.style.display = 'none';
        confirmButton.textContent = 'Schedule deletion';
        confirmButton.style.background = ''; // Reset to default
    }
}

// Confirm delete secret - NEW FUNCTION
async function confirmDeleteSecret(event) {
    event.preventDefault();

    const secretName = document.getElementById('delete-secret-name').value;
    const forceImmediate = document.getElementById('delete-force-immediate').checked;
    const recoveryDays = parseInt(document.getElementById('delete-recovery-days').value);

    // Validate recovery window
    if (!forceImmediate && (recoveryDays < 7 || recoveryDays > 30)) {
        showNotification('Recovery window must be between 7 and 30 days', 'error');
        return;
    }

    // Build the payload
    const payload = {
        SecretId: secretName
    };

    if (forceImmediate) {
        payload.ForceDeleteWithoutRecovery = true;
    } else {
        payload.RecoveryWindowInDays = recoveryDays;
    }

    try {
        const response = await fetch(API_BASE, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-amz-json-1.1',
                'X-Amz-Target': 'secretsmanager.DeleteSecret'
            },
            body: JSON.stringify(payload)
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || 'Failed to delete secret');
        }

        // Close modal
        closeModal('delete-secret-modal');

        // Show appropriate success message
        if (forceImmediate) {
            showNotification(`Secret "${secretName}" has been permanently deleted`, 'success');
        } else {
            const deletionDate = new Date(data.DeletionDate * 1000);
            showNotification(
                `Secret "${secretName}" is scheduled for deletion on ${deletionDate.toLocaleDateString()} ` +
                `(${recoveryDays} days from now)`,
                'success'
            );
        }

        // Reload the secrets list
        loadSecrets();

    } catch (error) {
        console.error('Error deleting secret:', error);
        showNotification('Failed to delete secret: ' + error.message, 'error');
    }
}

// ============================================================================
// INITIALIZATION
// ============================================================================

window.addEventListener('DOMContentLoaded', function () {
    // Initialize theme UI
    const currentTheme = getCookie('theme') || 'system';
    updateThemeUI(currentTheme);

    // Restore show deleted secrets checkbox state
    const showDeletedSecrets = localStorage.getItem('showDeletedSecrets');
    if (showDeletedSecrets !== null) {
        document.getElementById('show-deleted-secrets').checked = showDeletedSecrets === 'true';
    }

    // Load data for the active tab
    const activeTab = localStorage.getItem('activeTab') || 'sqs';

    // Display the currently active tab
    switchService(activeTab);
});
