/**
 * A13E Customer Support Automation
 *
 * This Google Apps Script integrates with:
 * - Gmail (reading/processing support emails)
 * - Google Sheets (ticket logging and CRM)
 * - Claude API (AI-powered classification and drafting)
 * - a13e API (customer context)
 * - Google Chat (urgent notifications)
 *
 * Setup Instructions:
 * 1. Create a new Google Apps Script project
 * 2. Copy all .gs files into the project
 * 3. Set Script Properties:
 *    - CLAUDE_API_KEY: Your Anthropic API key
 *    - A13E_SUPPORT_API_KEY: Support API key from a13e backend
 *    - SPREADSHEET_ID: ID of your support CRM spreadsheet
 *    - CHAT_WEBHOOK_URL: Google Chat webhook URL (optional)
 * 4. Run setupAllTriggers() to initialise automation
 *
 * @author a13e Support
 * @version 1.0.0
 */

// Configuration - loaded from Script Properties
const CONFIG = {
  get CLAUDE_API_KEY() {
    return PropertiesService.getScriptProperties().getProperty('CLAUDE_API_KEY');
  },
  get A13E_SUPPORT_API_KEY() {
    return PropertiesService.getScriptProperties().getProperty('A13E_SUPPORT_API_KEY');
  },
  get A13E_API_BASE() {
    // Use staging for testing, production for live
    const env = PropertiesService.getScriptProperties().getProperty('ENVIRONMENT') || 'production';
    return env === 'staging' ? 'https://api.staging.a13e.com' : 'https://api.a13e.com';
  },
  get SPREADSHEET_ID() {
    return PropertiesService.getScriptProperties().getProperty('SPREADSHEET_ID');
  },
  get CHAT_WEBHOOK_URL() {
    return PropertiesService.getScriptProperties().getProperty('CHAT_WEBHOOK_URL');
  }
};

// Claude API configuration
const CLAUDE_CONFIG = {
  MODEL: 'claude-sonnet-4-20250514',
  MAX_TOKENS: 1500,
  API_VERSION: '2023-06-01'
};

/**
 * Process new support emails
 * Triggered by time-based trigger (every 5 minutes)
 */
function processNewSupportEmails() {
  try {
    // Search for unread emails to support@a13e.com
    const threads = GmailApp.search('to:support@a13e.com is:unread', 0, 10);

    if (threads.length === 0) {
      Logger.log('No new support emails');
      return;
    }

    Logger.log(`Processing ${threads.length} threads`);

    threads.forEach(thread => {
      const messages = thread.getMessages();
      const latestMessage = messages[messages.length - 1];

      if (latestMessage.isUnread()) {
        try {
          processMessage(latestMessage, thread);
        } catch (e) {
          Logger.log(`Error processing message: ${e.message}`);
          // Star the message to indicate it needs attention
          latestMessage.star();
        }
      }
    });

  } catch (e) {
    Logger.log(`Error in processNewSupportEmails: ${e.message}`);
  }
}

/**
 * Process a single support message
 *
 * @param {GmailMessage} message - The Gmail message to process
 * @param {GmailThread} thread - The Gmail thread containing the message
 */
function processMessage(message, thread) {
  const senderEmail = extractEmail(message.getFrom());
  const subject = message.getSubject();
  const body = message.getPlainBody();

  Logger.log(`Processing: ${subject} from ${senderEmail}`);

  // 1. Fetch customer context from a13e API
  const context = fetchCustomerContext(senderEmail);

  // 2. Get AI classification and draft response
  const aiResponse = getAIAnalysis(subject, body, context);

  // 3. Log ticket to Google Sheets
  const ticketId = logTicket({
    email: senderEmail,
    subject: subject,
    body: body,
    context: context,
    aiResponse: aiResponse,
    messageId: message.getId(),
    threadId: thread.getId()
  });

  // 4. Apply Gmail labels
  applyLabels(thread, aiResponse, context);

  // 5. Create draft response if AI generated one
  if (aiResponse.draft_response) {
    saveDraftResponse(thread, aiResponse.draft_response, context);
  }

  // 6. Add customer context as a label note
  addContextNote(thread, context, aiResponse);

  // 7. Send notification for urgent/enterprise tickets
  if (shouldNotify(aiResponse, context)) {
    sendNotification(senderEmail, subject, context, aiResponse, ticketId);
  }

  // 8. Star the message to indicate it's been processed
  message.star();

  Logger.log(`Processed ticket ${ticketId}`);
}

/**
 * Fetch customer context from a13e API
 *
 * @param {string} email - Customer email address
 * @return {Object} Customer context or default object if not found
 */
function fetchCustomerContext(email) {
  if (!CONFIG.A13E_SUPPORT_API_KEY) {
    Logger.log('Warning: A13E_SUPPORT_API_KEY not configured');
    return { tier: 'unknown', notes: ['API key not configured'] };
  }

  try {
    const response = UrlFetchApp.fetch(
      `${CONFIG.A13E_API_BASE}/api/support/customer-context?email=${encodeURIComponent(email)}`,
      {
        headers: {
          'Authorization': `Bearer ${CONFIG.A13E_SUPPORT_API_KEY}`,
          'Content-Type': 'application/json'
        },
        muteHttpExceptions: true
      }
    );

    const statusCode = response.getResponseCode();

    if (statusCode === 200) {
      const context = JSON.parse(response.getContentText());
      Logger.log(`Found customer: ${context.organisation_name || email}, Tier: ${context.tier}`);
      return context;
    } else if (statusCode === 404) {
      Logger.log(`Customer not found: ${email}`);
      return {
        tier: 'unknown',
        email: email,
        notes: ['Customer not found in system - may be a new enquiry']
      };
    } else {
      Logger.log(`API error ${statusCode}: ${response.getContentText()}`);
      return {
        tier: 'unknown',
        notes: [`API returned ${statusCode}`]
      };
    }
  } catch (e) {
    Logger.log(`Context fetch error: ${e.message}`);
    return {
      tier: 'unknown',
      notes: ['Failed to fetch context - API may be unavailable']
    };
  }
}

/**
 * Get AI classification and draft response from Claude
 *
 * @param {string} subject - Email subject
 * @param {string} body - Email body
 * @param {Object} context - Customer context
 * @return {Object} AI analysis response
 */
function getAIAnalysis(subject, body, context) {
  if (!CONFIG.CLAUDE_API_KEY) {
    Logger.log('Warning: CLAUDE_API_KEY not configured');
    return defaultAIResponse();
  }

  const prompt = buildPrompt(subject, body, context);

  try {
    const response = UrlFetchApp.fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': CONFIG.CLAUDE_API_KEY,
        'anthropic-version': CLAUDE_CONFIG.API_VERSION
      },
      payload: JSON.stringify({
        model: CLAUDE_CONFIG.MODEL,
        max_tokens: CLAUDE_CONFIG.MAX_TOKENS,
        messages: [{
          role: 'user',
          content: prompt
        }]
      }),
      muteHttpExceptions: true
    });

    const statusCode = response.getResponseCode();

    if (statusCode === 200) {
      const result = JSON.parse(response.getContentText());
      if (result.content && result.content[0]) {
        return parseAIResponse(result.content[0].text);
      }
    } else {
      Logger.log(`Claude API error ${statusCode}: ${response.getContentText()}`);
    }

    return defaultAIResponse();
  } catch (e) {
    Logger.log(`Claude API error: ${e.message}`);
    return defaultAIResponse();
  }
}

/**
 * Build the prompt for Claude API
 *
 * @param {string} subject - Email subject
 * @param {string} body - Email body
 * @param {Object} context - Customer context
 * @return {string} Formatted prompt
 */
function buildPrompt(subject, body, context) {
  // Truncate body if too long
  const maxBodyLength = 2000;
  const truncatedBody = body.length > maxBodyLength
    ? body.substring(0, maxBodyLength) + '...[truncated]'
    : body;

  return `You are a support assistant for a13e, a cloud security detection coverage validator.

CUSTOMER CONTEXT:
- Subscription Tier: ${context.tier || 'Unknown'}
- Organisation: ${context.organisation_name || 'Unknown'}
- Cloud Accounts: ${context.cloud_accounts_count || 0}/${context.max_accounts_allowed || '?'}
- Coverage Score: ${context.coverage_score || 'N/A'}%
- Open Security Gaps: ${context.open_gaps || 0}
- Last Scan: ${context.last_scan || 'Never'}
- Last Login: ${context.last_login || 'Unknown'}
- Account Status: ${context.is_active ? 'Active' : 'Inactive'}
- MFA Enabled: ${context.mfa_enabled ? 'Yes' : 'No'}
${context.notes && context.notes.length > 0 ? `- Notes: ${context.notes.join(', ')}` : ''}

SUPPORT EMAIL:
Subject: ${subject}
Body:
${truncatedBody}

Analyse this support request and respond with valid JSON only:
{
  "category": "billing|technical|feature-request|bug-report|account|security",
  "priority": "urgent|normal|low",
  "summary": "One sentence summary of the issue",
  "draft_response": "Professional, helpful response in British English. Reference their specific situation where helpful. Sign off as 'The a13e Team'",
  "relevant_kb_topics": ["topic1", "topic2"],
  "requires_escalation": false,
  "escalation_reason": null,
  "sentiment": "positive|neutral|frustrated|urgent"
}

PRIORITY GUIDELINES:
- URGENT: Service outage, security incident, billing dispute, Enterprise tier, data loss
- NORMAL: Feature questions, how-to help, general enquiries, Individual/Pro tier
- LOW: Feature requests, feedback, non-blocking issues, FREE tier general questions

RESPONSE GUIDELINES:
- Use British English (colour, organisation, behaviour)
- Be concise but thorough
- Reference their specific situation (tier, coverage, gaps) where helpful
- For billing: FREE (1 account), Individual (6 accounts, GBP29/month), Pro (500 accounts, GBP250/month), Enterprise (custom)
- Include relevant next steps
- Sign off as "The a13e Team"`;
}

/**
 * Parse AI response from Claude
 *
 * @param {string} text - Response text from Claude
 * @return {Object} Parsed response or default
 */
function parseAIResponse(text) {
  try {
    // Extract JSON from the response (Claude might include explanation text)
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]);
      // Validate required fields
      if (parsed.category && parsed.priority) {
        return parsed;
      }
    }
  } catch (e) {
    Logger.log(`Failed to parse AI response: ${e.message}`);
    Logger.log(`Response text: ${text.substring(0, 500)}`);
  }
  return defaultAIResponse();
}

/**
 * Default AI response when API fails or parsing fails
 *
 * @return {Object} Default response object
 */
function defaultAIResponse() {
  return {
    category: 'technical',
    priority: 'normal',
    summary: 'New support request - manual review required',
    draft_response: null,
    relevant_kb_topics: [],
    requires_escalation: false,
    escalation_reason: null,
    sentiment: 'neutral'
  };
}

/**
 * Log ticket to Google Sheets
 *
 * @param {Object} data - Ticket data
 * @return {string} Generated ticket ID
 */
function logTicket(data) {
  if (!CONFIG.SPREADSHEET_ID) {
    Logger.log('Warning: SPREADSHEET_ID not configured');
    return Utilities.getUuid();
  }

  try {
    const sheet = SpreadsheetApp.openById(CONFIG.SPREADSHEET_ID).getSheetByName('Tickets');

    if (!sheet) {
      Logger.log('Warning: Tickets sheet not found');
      return Utilities.getUuid();
    }

    const ticketId = Utilities.getUuid().substring(0, 8).toUpperCase();
    const now = new Date();

    const row = [
      ticketId,                                    // Ticket ID
      now,                                         // Received At
      data.email,                                  // Customer Email
      data.context.organisation_name || '',        // Organisation
      data.context.tier || 'unknown',              // Tier
      data.subject,                                // Subject
      data.aiResponse.category || 'unknown',       // Category
      data.aiResponse.priority || 'normal',        // Priority
      'Open',                                      // Status
      '',                                          // Response Sent At
      '',                                          // Resolution Time (hrs)
      data.aiResponse.summary || '',               // Notes/Summary
      data.aiResponse.draft_response ? true : false, // AI Draft Available
      data.messageId,                              // Message ID
      data.threadId                                // Thread ID
    ];

    sheet.appendRow(row);

    // Update customer context cache
    updateContextCache(data.email, data.context);

    return ticketId;
  } catch (e) {
    Logger.log(`Error logging ticket: ${e.message}`);
    return Utilities.getUuid().substring(0, 8).toUpperCase();
  }
}

/**
 * Update customer context cache in Google Sheets
 *
 * @param {string} email - Customer email
 * @param {Object} context - Customer context
 */
function updateContextCache(email, context) {
  try {
    const sheet = SpreadsheetApp.openById(CONFIG.SPREADSHEET_ID).getSheetByName('Customer Context Cache');

    if (!sheet) {
      Logger.log('Warning: Customer Context Cache sheet not found');
      return;
    }

    const data = sheet.getDataRange().getValues();

    // Find existing row or add new
    let rowIndex = -1;
    for (let i = 1; i < data.length; i++) {
      if (data[i][0] === email) {
        rowIndex = i + 1;
        break;
      }
    }

    const row = [
      email,
      new Date(),
      context.tier || 'unknown',
      context.organisation_name || '',
      context.cloud_accounts_count || 0,
      context.last_scan || '',
      context.coverage_score || '',
      context.open_gaps || 0,
      JSON.stringify(context)
    ];

    if (rowIndex > 0) {
      sheet.getRange(rowIndex, 1, 1, row.length).setValues([row]);
    } else {
      sheet.appendRow(row);
    }
  } catch (e) {
    Logger.log(`Error updating context cache: ${e.message}`);
  }
}

/**
 * Apply Gmail labels based on AI classification
 *
 * @param {GmailThread} thread - Gmail thread
 * @param {Object} aiResponse - AI analysis response
 * @param {Object} context - Customer context
 */
function applyLabels(thread, aiResponse, context) {
  const labels = [
    `Support/Category/${capitalise(aiResponse.category || 'technical')}`,
    `Support/Priority/${capitalise(aiResponse.priority || 'normal')}`,
    'Support/Status/Awaiting-Response'
  ];

  // Add tier label
  if (context.tier && context.tier !== 'unknown') {
    labels.push(`Support/Tier/${capitalise(context.tier)}`);
  }

  labels.forEach(labelPath => {
    try {
      const label = GmailApp.getUserLabelByName(labelPath);
      if (label) {
        thread.addLabel(label);
      } else {
        // Create label if it doesn't exist
        const newLabel = GmailApp.createLabel(labelPath);
        thread.addLabel(newLabel);
      }
    } catch (e) {
      Logger.log(`Could not apply label ${labelPath}: ${e.message}`);
    }
  });
}

/**
 * Save draft response in Gmail
 *
 * @param {GmailThread} thread - Gmail thread
 * @param {string} draftText - Draft response text
 * @param {Object} context - Customer context
 */
function saveDraftResponse(thread, draftText, context) {
  if (!draftText) return;

  try {
    const messages = thread.getMessages();
    const lastMessage = messages[messages.length - 1];

    // Add context header to draft
    const contextHeader = `[AI-Generated Draft - Review before sending]
[Customer: ${context.organisation_name || context.email || 'Unknown'} | Tier: ${capitalise(context.tier || 'unknown')}]

`;

    // Create a draft reply
    lastMessage.createDraftReply(contextHeader + draftText, {
      from: 'support@a13e.com'
    });

    Logger.log('Draft response saved');
  } catch (e) {
    Logger.log(`Failed to create draft: ${e.message}`);
  }
}

/**
 * Add customer context as a note (using a specific label)
 *
 * @param {GmailThread} thread - Gmail thread
 * @param {Object} context - Customer context
 * @param {Object} aiResponse - AI analysis
 */
function addContextNote(thread, context, aiResponse) {
  // Context is visible through labels and the CRM spreadsheet
  // This function can be extended to add notes via Gmail API if needed
  Logger.log(`Context applied for ${context.email || 'unknown'}`);
}

/**
 * Determine if notification should be sent
 *
 * @param {Object} aiResponse - AI analysis
 * @param {Object} context - Customer context
 * @return {boolean} Whether to send notification
 */
function shouldNotify(aiResponse, context) {
  // Always notify for urgent priority
  if (aiResponse.priority === 'urgent') return true;

  // Always notify for Enterprise tier
  if (context.tier === 'enterprise') return true;

  // Notify for security-related issues
  if (aiResponse.category === 'security') return true;

  // Notify if AI suggests escalation
  if (aiResponse.requires_escalation) return true;

  // Notify for frustrated customers
  if (aiResponse.sentiment === 'frustrated') return true;

  return false;
}

/**
 * Send notification via Google Chat
 *
 * @param {string} email - Customer email
 * @param {string} subject - Email subject
 * @param {Object} context - Customer context
 * @param {Object} aiResponse - AI analysis
 * @param {string} ticketId - Ticket ID
 */
function sendNotification(email, subject, context, aiResponse, ticketId) {
  if (!CONFIG.CHAT_WEBHOOK_URL) {
    Logger.log('Chat notification skipped - webhook not configured');
    return;
  }

  try {
    // Build notification colour based on priority
    const colours = {
      urgent: '#dc3545',   // Red
      normal: '#ffc107',   // Yellow
      low: '#28a745'       // Green
    };
    const colour = colours[aiResponse.priority] || colours.normal;

    const message = {
      cards: [{
        header: {
          title: `${aiResponse.priority === 'urgent' ? '[URGENT] ' : ''}New Support Ticket`,
          subtitle: `Ticket #${ticketId}`,
          imageUrl: 'https://app.a13e.com/logo.png',
          imageStyle: 'AVATAR'
        },
        sections: [{
          widgets: [
            {
              keyValue: {
                topLabel: 'From',
                content: email,
                contentMultiline: false
              }
            },
            {
              keyValue: {
                topLabel: 'Subject',
                content: subject.substring(0, 100),
                contentMultiline: false
              }
            },
            {
              keyValue: {
                topLabel: 'Tier',
                content: capitalise(context.tier || 'Unknown'),
                contentMultiline: false
              }
            },
            {
              keyValue: {
                topLabel: 'Category',
                content: capitalise(aiResponse.category || 'Unknown'),
                contentMultiline: false
              }
            },
            {
              keyValue: {
                topLabel: 'Priority',
                content: capitalise(aiResponse.priority || 'Normal'),
                contentMultiline: false
              }
            }
          ]
        },
        {
          widgets: [{
            textParagraph: {
              text: `<b>Summary:</b> ${aiResponse.summary || 'No summary available'}`
            }
          }]
        }]
      }]
    };

    UrlFetchApp.fetch(CONFIG.CHAT_WEBHOOK_URL, {
      method: 'POST',
      contentType: 'application/json',
      payload: JSON.stringify(message)
    });

    Logger.log('Notification sent');
  } catch (e) {
    Logger.log(`Failed to send notification: ${e.message}`);
  }
}

// ============ Utility Functions ============

/**
 * Extract email address from "Name <email>" format
 *
 * @param {string} fromHeader - From header value
 * @return {string} Extracted email address
 */
function extractEmail(fromHeader) {
  const match = fromHeader.match(/<(.+?)>/);
  return match ? match[1] : fromHeader.trim();
}

/**
 * Capitalise first letter of a string
 *
 * @param {string} str - Input string
 * @return {string} Capitalised string
 */
function capitalise(str) {
  if (!str) return '';
  return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
}

// ============ Setup Functions ============

/**
 * Set up all required Gmail labels
 * Run this once during initial setup
 */
function setupLabels() {
  const labels = [
    'Support/Category/Billing',
    'Support/Category/Technical',
    'Support/Category/Feature-Request',
    'Support/Category/Bug-Report',
    'Support/Category/Account',
    'Support/Category/Security',
    'Support/Priority/Urgent',
    'Support/Priority/Normal',
    'Support/Priority/Low',
    'Support/Status/Awaiting-Response',
    'Support/Status/In-Progress',
    'Support/Status/Pending-Customer',
    'Support/Status/Resolved',
    'Support/Tier/Free',
    'Support/Tier/Individual',
    'Support/Tier/Pro',
    'Support/Tier/Enterprise',
    'Support/Tier/Unknown'
  ];

  labels.forEach(labelPath => {
    try {
      GmailApp.createLabel(labelPath);
      Logger.log(`Created: ${labelPath}`);
    } catch (e) {
      Logger.log(`Already exists or error: ${labelPath}`);
    }
  });

  Logger.log('Label setup complete');
}

/**
 * Set up all triggers for the support system
 * Run this once during initial setup
 */
function setupAllTriggers() {
  // Remove existing triggers
  const triggers = ScriptApp.getProjectTriggers();
  triggers.forEach(trigger => {
    if (trigger.getHandlerFunction() === 'processNewSupportEmails' ||
        trigger.getHandlerFunction() === 'updateDailyMetrics' ||
        trigger.getHandlerFunction() === 'sendWeeklyReport') {
      ScriptApp.deleteTrigger(trigger);
    }
  });

  // Process emails every 5 minutes
  ScriptApp.newTrigger('processNewSupportEmails')
    .timeBased()
    .everyMinutes(5)
    .create();

  // Daily metrics update at 9 AM
  ScriptApp.newTrigger('updateDailyMetrics')
    .timeBased()
    .atHour(9)
    .everyDays(1)
    .create();

  // Weekly report on Monday at 9 AM
  ScriptApp.newTrigger('sendWeeklyReport')
    .timeBased()
    .onWeekDay(ScriptApp.WeekDay.MONDAY)
    .atHour(9)
    .create();

  Logger.log('Triggers configured:');
  Logger.log('- processNewSupportEmails: Every 5 minutes');
  Logger.log('- updateDailyMetrics: Daily at 9 AM');
  Logger.log('- sendWeeklyReport: Monday at 9 AM');
}

/**
 * Test function to verify API connectivity
 */
function testAPIs() {
  Logger.log('Testing API connectivity...');

  // Test a13e API
  if (CONFIG.A13E_SUPPORT_API_KEY) {
    const testContext = fetchCustomerContext('test@example.com');
    Logger.log(`a13e API: ${testContext.notes ? 'Connected' : 'Error'}`);
  } else {
    Logger.log('a13e API: Not configured (A13E_SUPPORT_API_KEY missing)');
  }

  // Test Claude API
  if (CONFIG.CLAUDE_API_KEY) {
    const testResponse = getAIAnalysis('Test', 'This is a test message', { tier: 'test' });
    Logger.log(`Claude API: ${testResponse.category ? 'Connected' : 'Error'}`);
  } else {
    Logger.log('Claude API: Not configured (CLAUDE_API_KEY missing)');
  }

  // Test Spreadsheet
  if (CONFIG.SPREADSHEET_ID) {
    try {
      const sheet = SpreadsheetApp.openById(CONFIG.SPREADSHEET_ID);
      Logger.log(`Spreadsheet: Connected (${sheet.getName()})`);
    } catch (e) {
      Logger.log(`Spreadsheet: Error - ${e.message}`);
    }
  } else {
    Logger.log('Spreadsheet: Not configured (SPREADSHEET_ID missing)');
  }

  Logger.log('API test complete');
}
