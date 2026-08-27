const SUPABASE_URL = "https://lvkzvbhzybzhnrjdsrq.supabase.co";
const SUPABASE_KEY = "sb_publishable_8yLutmmiNlE_S2UUXzrCjA_qfOhHbbY";
const _supabase = supabase.createClient(SUPABASE_URL, SUPABASE_KEY);

// تحميل البيانات من السحابة عند فتح الصفحة
async function loadDataFromSupabase() {
  try {
    const { data: users } = await _supabase.from("users").select("*");
    const { data: lectures } = await _supabase.from("lectures").select("*");
    const { data: announcements } = await _supabase
      .from("announcements")
      .select("*");
    const { data: absences } = await _supabase.from("absences").select("*");
    const { data: grades } = await _supabase.from("grades").select("*");

    if (users) window.users = users;
    if (lectures) window.lectures = lectures;
    if (announcements) window.announcements = announcements;
    if (absences) window.absences = absences;
    if (grades) window.grades = grades;

    console.log("تم تحميل البيانات بنجاح من Supabase");
  } catch (error) {
    console.error("خطأ في جلب البيانات:", error);
  }
}

// استدعاء التحميل فور فتح الموقع
loadDataFromSupabase();
