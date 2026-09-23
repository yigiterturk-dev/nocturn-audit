// HOLE — insecure CORS: open to every origin and carrying credentials.
export async function GET() {
  return new Response(JSON.stringify({ veri: [] }), {
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Credentials": "true",
    },
  });
}
