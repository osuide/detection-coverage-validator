/**
 * Metrics and Reporting Functions for A13E Support
 *
 * This file contains functions for:
 * - Daily metrics calculation
 * - Weekly report generation
 * - Performance tracking
 */

/**
 * Update daily metrics in the Metrics sheet
 * Triggered daily at 9 AM
 */
function updateDailyMetrics() {
  if (!CONFIG.SPREADSHEET_ID) {
    Logger.log('Metrics update skipped - SPREADSHEET_ID not configured');
    return;
  }

  try {
    const spreadsheet = SpreadsheetApp.openById(CONFIG.SPREADSHEET_ID);
    const ticketsSheet = spreadsheet.getSheetByName('Tickets');
    const metricsSheet = spreadsheet.getSheetByName('Metrics');

    if (!ticketsSheet || !metricsSheet) {
      Logger.log('Warning: Required sheets not found');
      return;
    }

    const today = new Date();
    const weekStart = getWeekStart(today);

    const tickets = ticketsSheet.getDataRange().getValues();

    // Calculate metrics for this week
    let received = 0;
    let resolved = 0;
    let totalResponseTimeHours = 0;
    let responsesCount = 0;
    let totalResolutionTimeHours = 0;
    let resolutionsCount = 0;
    let aiDraftAvailable = 0;

    // Skip header row
    for (let i = 1; i < tickets.length; i++) {
      const row = tickets[i];
      const receivedAt = new Date(row[1]);

      // Check if ticket is from this week
      if (receivedAt >= weekStart && receivedAt <= today) {
        received++;

        // Count resolved tickets
        if (row[8] === 'Resolved') {
          resolved++;

          // Calculate resolution time if available
          const responseSentAt = row[9];
          if (responseSentAt) {
            const responseTime = (new Date(responseSentAt) - receivedAt) / (1000 * 60 * 60);
            totalResponseTimeHours += responseTime;
            responsesCount++;
          }
        }

        // Count tickets with AI draft
        if (row[12]) {
          aiDraftAvailable++;
        }
      }
    }

    // Calculate averages
    const avgResponseTime = responsesCount > 0 ? totalResponseTimeHours / responsesCount : 0;
    const avgResolutionTime = resolutionsCount > 0 ? totalResolutionTimeHours / resolutionsCount : 0;
    const aiDraftUsagePercent = received > 0 ? Math.round((aiDraftAvailable / received) * 100) : 0;

    // Find or create row for this week
    const metricsData = metricsSheet.getDataRange().getValues();
    let rowIndex = -1;

    for (let i = 1; i < metricsData.length; i++) {
      const rowDate = new Date(metricsData[i][0]);
      if (rowDate.getTime() === weekStart.getTime()) {
        rowIndex = i + 1;
        break;
      }
    }

    const metricsRow = [
      weekStart,
      received,
      resolved,
      avgResponseTime.toFixed(1),
      avgResolutionTime.toFixed(1),
      '', // CSAT score (manual entry)
      aiDraftUsagePercent
    ];

    if (rowIndex > 0) {
      metricsSheet.getRange(rowIndex, 1, 1, metricsRow.length).setValues([metricsRow]);
      Logger.log(`Updated metrics for week of ${weekStart.toDateString()}`);
    } else {
      metricsSheet.appendRow(metricsRow);
      Logger.log(`Added metrics for week of ${weekStart.toDateString()}`);
    }

  } catch (e) {
    Logger.log(`Error updating metrics: ${e.message}`);
  }
}

/**
 * Send weekly support report via email
 * Triggered Monday at 9 AM
 */
function sendWeeklyReport() {
  if (!CONFIG.SPREADSHEET_ID) {
    Logger.log('Weekly report skipped - SPREADSHEET_ID not configured');
    return;
  }

  try {
    const spreadsheet = SpreadsheetApp.openById(CONFIG.SPREADSHEET_ID);
    const metricsSheet = spreadsheet.getSheetByName('Metrics');
    const ticketsSheet = spreadsheet.getSheetByName('Tickets');

    if (!metricsSheet || !ticketsSheet) {
      Logger.log('Warning: Required sheets not found');
      return;
    }

    // Get last week's metrics
    const today = new Date();
    const lastWeekStart = getWeekStart(new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000));

    const metricsData = metricsSheet.getDataRange().getValues();
    let lastWeekMetrics = null;

    for (let i = 1; i < metricsData.length; i++) {
      const rowDate = new Date(metricsData[i][0]);
      if (rowDate.getTime() === lastWeekStart.getTime()) {
        lastWeekMetrics = metricsData[i];
        break;
      }
    }

    // Get open tickets count
    const tickets = ticketsSheet.getDataRange().getValues();
    let openTickets = 0;
    let urgentOpen = 0;

    for (let i = 1; i < tickets.length; i++) {
      if (tickets[i][8] === 'Open' || tickets[i][8] === 'Awaiting-Response') {
        openTickets++;
        if (tickets[i][7] === 'urgent') {
          urgentOpen++;
        }
      }
    }

    // Build report
    const weekEnding = Utilities.formatDate(today, Session.getScriptTimeZone(), 'dd MMM yyyy');
    const subject = `Weekly Support Report - Week ending ${weekEnding}`;

    let body = `A13E Support - Weekly Summary\n`;
    body += `Week ending: ${weekEnding}\n\n`;

    if (lastWeekMetrics) {
      body += `LAST WEEK'S METRICS:\n`;
      body += `- Tickets Received: ${lastWeekMetrics[1]}\n`;
      body += `- Tickets Resolved: ${lastWeekMetrics[2]}\n`;
      body += `- Avg Response Time: ${lastWeekMetrics[3]} hours\n`;
      body += `- AI Draft Usage: ${lastWeekMetrics[6]}%\n\n`;
    } else {
      body += `No metrics available for last week.\n\n`;
    }

    body += `CURRENT STATUS:\n`;
    body += `- Open Tickets: ${openTickets}\n`;
    body += `- Urgent Open: ${urgentOpen}\n\n`;

    body += `View full metrics: ${spreadsheet.getUrl()}\n`;

    // Send to the script owner
    GmailApp.sendEmail(
      Session.getActiveUser().getEmail(),
      subject,
      body
    );

    Logger.log('Weekly report sent');

  } catch (e) {
    Logger.log(`Error sending weekly report: ${e.message}`);
  }
}

/**
 * Get the start of the week (Monday) for a given date
 *
 * @param {Date} date - Input date
 * @return {Date} Start of the week (Monday at 00:00)
 */
function getWeekStart(date) {
  const d = new Date(date);
  const day = d.getDay();
  const diff = d.getDate() - day + (day === 0 ? -6 : 1); // Adjust when day is Sunday
  const weekStart = new Date(d.setDate(diff));
  weekStart.setHours(0, 0, 0, 0);
  return weekStart;
}

/**
 * Generate a metrics summary for a specific period
 *
 * @param {Date} startDate - Period start
 * @param {Date} endDate - Period end
 * @return {Object} Metrics summary
 */
function getMetricsSummary(startDate, endDate) {
  if (!CONFIG.SPREADSHEET_ID) {
    return { error: 'Spreadsheet not configured' };
  }

  try {
    const spreadsheet = SpreadsheetApp.openById(CONFIG.SPREADSHEET_ID);
    const ticketsSheet = spreadsheet.getSheetByName('Tickets');

    if (!ticketsSheet) {
      return { error: 'Tickets sheet not found' };
    }

    const tickets = ticketsSheet.getDataRange().getValues();

    let totalReceived = 0;
    let totalResolved = 0;
    let byCategory = {};
    let byPriority = {};
    let byTier = {};

    for (let i = 1; i < tickets.length; i++) {
      const row = tickets[i];
      const receivedAt = new Date(row[1]);

      if (receivedAt >= startDate && receivedAt <= endDate) {
        totalReceived++;

        if (row[8] === 'Resolved') {
          totalResolved++;
        }

        // Count by category
        const category = row[6] || 'unknown';
        byCategory[category] = (byCategory[category] || 0) + 1;

        // Count by priority
        const priority = row[7] || 'normal';
        byPriority[priority] = (byPriority[priority] || 0) + 1;

        // Count by tier
        const tier = row[4] || 'unknown';
        byTier[tier] = (byTier[tier] || 0) + 1;
      }
    }

    return {
      period: {
        start: startDate,
        end: endDate
      },
      totalReceived: totalReceived,
      totalResolved: totalResolved,
      resolutionRate: totalReceived > 0 ? Math.round((totalResolved / totalReceived) * 100) : 0,
      byCategory: byCategory,
      byPriority: byPriority,
      byTier: byTier
    };

  } catch (e) {
    return { error: e.message };
  }
}

/**
 * Get list of currently open tickets
 *
 * @return {Array} Array of open ticket objects
 */
function getOpenTickets() {
  if (!CONFIG.SPREADSHEET_ID) {
    return [];
  }

  try {
    const spreadsheet = SpreadsheetApp.openById(CONFIG.SPREADSHEET_ID);
    const ticketsSheet = spreadsheet.getSheetByName('Tickets');

    if (!ticketsSheet) {
      return [];
    }

    const tickets = ticketsSheet.getDataRange().getValues();
    const headers = tickets[0];
    const openTickets = [];

    for (let i = 1; i < tickets.length; i++) {
      const row = tickets[i];
      const status = row[8];

      if (status === 'Open' || status === 'Awaiting-Response' || status === 'In-Progress') {
        openTickets.push({
          ticketId: row[0],
          receivedAt: row[1],
          email: row[2],
          organisation: row[3],
          tier: row[4],
          subject: row[5],
          category: row[6],
          priority: row[7],
          status: row[8],
          ageHours: Math.round((new Date() - new Date(row[1])) / (1000 * 60 * 60))
        });
      }
    }

    // Sort by priority (urgent first) then by age (oldest first)
    const priorityOrder = { 'urgent': 0, 'normal': 1, 'low': 2 };
    openTickets.sort((a, b) => {
      const priorityDiff = (priorityOrder[a.priority] || 1) - (priorityOrder[b.priority] || 1);
      if (priorityDiff !== 0) return priorityDiff;
      return b.ageHours - a.ageHours;
    });

    return openTickets;

  } catch (e) {
    Logger.log(`Error getting open tickets: ${e.message}`);
    return [];
  }
}

/**
 * Mark a ticket as resolved
 *
 * @param {string} ticketId - Ticket ID to resolve
 * @param {string} notes - Resolution notes
 * @return {boolean} Success
 */
function resolveTicket(ticketId, notes) {
  if (!CONFIG.SPREADSHEET_ID) {
    return false;
  }

  try {
    const spreadsheet = SpreadsheetApp.openById(CONFIG.SPREADSHEET_ID);
    const ticketsSheet = spreadsheet.getSheetByName('Tickets');

    if (!ticketsSheet) {
      return false;
    }

    const tickets = ticketsSheet.getDataRange().getValues();

    for (let i = 1; i < tickets.length; i++) {
      if (tickets[i][0] === ticketId) {
        const rowIndex = i + 1;
        const receivedAt = new Date(tickets[i][1]);
        const now = new Date();
        const resolutionTimeHours = ((now - receivedAt) / (1000 * 60 * 60)).toFixed(1);

        // Update status
        ticketsSheet.getRange(rowIndex, 9).setValue('Resolved');
        // Update response sent at
        ticketsSheet.getRange(rowIndex, 10).setValue(now);
        // Update resolution time
        ticketsSheet.getRange(rowIndex, 11).setValue(resolutionTimeHours);
        // Update notes
        if (notes) {
          const existingNotes = tickets[i][11] || '';
          ticketsSheet.getRange(rowIndex, 12).setValue(existingNotes + (existingNotes ? '\n' : '') + `[Resolved] ${notes}`);
        }

        Logger.log(`Ticket ${ticketId} marked as resolved`);
        return true;
      }
    }

    Logger.log(`Ticket ${ticketId} not found`);
    return false;

  } catch (e) {
    Logger.log(`Error resolving ticket: ${e.message}`);
    return false;
  }
}
