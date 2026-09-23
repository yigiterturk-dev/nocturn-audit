import { createClient } from "@supabase/supabase-js";

// The RLS rule is only meaningful in a real Supabase client project (anon key
// plus PostgREST access). The canary has to carry that context, or the rule
// rightly never runs.
export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
);
