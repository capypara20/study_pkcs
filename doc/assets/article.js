/* =====================================================================
 * article.js — 記事型(長尺スクロール)ドキュメント用の軽量制御
 *
 * 05(関数リファレンス)のように .slide ページ送りに馴染まない、表が主役の
 * 文書で使う。deck.js は .slide が無いと何もしないため、こちらを読み込む。
 * 役割:
 *   - INDEX モーダルの目次を本文の <h2 id> から自動生成
 *   - スクロール位置に応じて topbar の章番号(#curNum)を更新
 *   - 目次クリック / Esc 開閉
 * ===================================================================== */
(function () {
  "use strict";

  const heads = Array.from(document.querySelectorAll(".article h2[id]"));
  const curNumEl = document.getElementById("curNum");
  const totalNumEl = document.getElementById("totalNum");
  const tocBtn = document.getElementById("tocBtn");
  const tocModal = document.getElementById("tocModal");
  const tocList = document.getElementById("tocList");

  if (heads.length === 0) return;

  if (totalNumEl) totalNumEl.textContent = String(heads.length).padStart(2, "0");

  // ---- 目次生成 ------------------------------------------------------
  if (tocList) {
    heads.forEach((h, i) => {
      const li = document.createElement("li");
      const a = document.createElement("a");
      a.href = `#${h.id}`;
      a.innerHTML =
        `<span class="toc-num">${String(i + 1).padStart(2, "0")}</span>` +
        `<span class="toc-title"></span>`;
      // 見出しテキスト（先頭の番号記号などはそのまま）を安全に挿入
      a.querySelector(".toc-title").textContent = h.textContent.trim();
      a.addEventListener("click", () => closeToc());
      li.appendChild(a);
      tocList.appendChild(li);
    });
  }

  // ---- モーダル開閉 --------------------------------------------------
  function openToc() { if (tocModal) tocModal.classList.add("show"); }
  function closeToc() { if (tocModal) tocModal.classList.remove("show"); }
  function tocIsOpen() { return tocModal ? tocModal.classList.contains("show") : false; }

  if (tocBtn) {
    tocBtn.addEventListener("click", () => (tocIsOpen() ? closeToc() : openToc()));
  }
  if (tocModal) {
    tocModal.addEventListener("click", (e) => { if (e.target === tocModal) closeToc(); });
  }
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeToc();
  });

  // ---- スクロール連動で章番号を更新 ---------------------------------
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          const idx = heads.indexOf(entry.target);
          if (idx >= 0 && curNumEl) {
            curNumEl.textContent = String(idx + 1).padStart(2, "0");
          }
        }
      });
    },
    { rootMargin: "-10% 0px -80% 0px", threshold: 0 }
  );
  heads.forEach((h) => observer.observe(h));
})();
