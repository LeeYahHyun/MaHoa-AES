async function processAES(mode) {
  const input = document.getElementById("input").value;
  const key = document.getElementById("key").value;

  try {
    const response = await fetch("/convert", {
      method: "POST",

      headers: {
        "Content-Type": "application/json",
      },

      body: JSON.stringify({
        input: input,
        key: key,
        mode: mode,
      }),
    });

    const data = await response.json();

    if (data.success) {
      document.getElementById("output").value = data.result;
    } else {
      alert(data.error);
    }
  } catch (error) {
    alert("Không thể kết nối đến Flask!");
  }
}
