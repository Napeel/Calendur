import Anthropic from '@anthropic-ai/sdk';

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const SYSTEM_PROMPT = `You are an event parser. Extract calendar event details from plain text.

Return ONLY valid JSON with these fields:
- title (string): event name/title
- start (string): ISO 8601 datetime without timezone offset (e.g., "2026-04-08T12:00:00")
- end (string): ISO 8601 datetime without timezone offset. If no end time or duration is given, use the provided defaultDuration (in minutes) from the start time.
- timezone (string): IANA timezone (e.g., "America/New_York"). If a timezone is mentioned in the text, use it. Otherwise use the provided user timezone.
- location (string | null): location if mentioned, null otherwise
- recurrence (string[] | null): RFC 5545 RRULE strings if the event is recurring, null otherwise. Example: ["RRULE:FREQ=WEEKLY;BYDAY=MO"]
- description (string | null): any extra details that don't fit other fields, null otherwise

Rules:
- Use the provided currentDate to resolve relative dates like "tomorrow", "next Monday", etc.
- For ambiguous times like "3 o'clock", prefer PM for social events and AM for work events.
- If no date is mentioned at all, use the next occurrence that makes sense from currentDate.
- Return ONLY the JSON object, no markdown, no explanation.`;

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { text, timezone, currentDate, defaultDuration } = req.body;

  if (!text) {
    return res.status(400).json({ error: 'Missing required field: text' });
  }

  const userPrompt = `Parse this event description:
"${text}"

Context:
- Current date/time: ${currentDate || new Date().toISOString()}
- User timezone: ${timezone || 'UTC'}
- Default duration: ${defaultDuration || 30} minutes`;

  try {
    const response = await client.messages.create({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 512,
      system: SYSTEM_PROMPT,
      messages: [{ role: 'user', content: userPrompt }],
    });

    const content = response.content[0].text;
    const parsed = JSON.parse(content);

    return res.status(200).json(parsed);
  } catch (error) {
    if (error instanceof SyntaxError) {
      return res.status(500).json({ error: 'Failed to parse Claude response as JSON' });
    }
    return res.status(500).json({ error: error.message || 'Internal server error' });
  }
}
