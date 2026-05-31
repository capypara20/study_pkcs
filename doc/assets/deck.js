/* =====================================================================
 * deck.js — 縦スクロール式スライドの共通制御スクリプト
 *
 * 3つのHTML（01 / 02 / Rust生FFI実装）で共通利用する。
 * 主な役割:
 *   - 目次(TOC)の自動生成（章区切りの自動判定つき）
 *   - 現在スライド番号の追跡（IntersectionObserver）
 *   - 前へ/次へボタン・キーボード操作
 *   - スマホのスワイプ操作（上下フリックでスライド移動）
 *
 * 以前は各HTMLにバラバラのスクリプトが埋め込まれており、
 *   - スワイプが未完成（touchstartだけで何も起きない）
 *   - prevBtn/nextBtn を定義前に参照していて ReferenceError の恐れ
 *   - TOCの章判定の条件式に演算子優先順位のミス
 * といった不具合があった。本ファイルはそれらを修正した統合版。
 * ===================================================================== */
(function () {
  "use strict";

  // ---- 必須要素の取得（どれか欠けていたら何もしない） ----------------
  const slides = Array.from(document.querySelectorAll(".slide"));
  const totalNumEl = document.getElementById("totalNum");
  const curNumEl = document.getElementById("curNum");
  const prevBtn = document.getElementById("prevBtn");
  const nextBtn = document.getElementById("nextBtn");
  const tocBtn = document.getElementById("tocBtn");
  const tocModal = document.getElementById("tocModal");
  const tocList = document.getElementById("tocList");

  if (slides.length === 0) return;

  const total = slides.length;
  let current = 0;

  // 各スライドに連番idを付与（slide-0 .. slide-(N-1)）
  slides.forEach((slide, i) => {
    slide.id = `slide-${i}`;
  });

  if (totalNumEl) {
    totalNumEl.textContent = String(total).padStart(2, "0");
  }

  // ---- スライド移動 --------------------------------------------------
  function goTo(index) {
    if (index < 0 || index >= total) return;
    current = index;
    slides[index].scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // ---- 章区切りの自動判定 --------------------------------------------
  // .slide-tag に「修飾クラス（ch1, design, impl など）」が付いていて、
  // 直前のスライドと修飾クラスが変わったスライドを章の先頭とみなす。
  // タイトル(0)・目次(1)も章見出し扱いにする。ページ構造に依存しない。
  function tagModifier(slide) {
    const tag = slide.querySelector(".slide-tag");
    if (!tag) return null;
    // "slide-tag" 以外のクラス名を修飾クラスとして返す
    const extra = Array.from(tag.classList).filter((c) => c !== "slide-tag");
    return extra.length ? extra.join(" ") : null;
  }

  function isChapterHead(i) {
    if (i <= 1) return true; // タイトル・目次
    const cur = tagModifier(slides[i]);
    if (!cur) return false;
    const prev = tagModifier(slides[i - 1]);
    return cur !== prev;
  }

  // ---- 目次(TOC)の生成 ----------------------------------------------
  if (tocList) {
    slides.forEach((slide, i) => {
      const title = slide.getAttribute("data-title") || `Slide ${i + 1}`;
      const li = document.createElement("li");
      const a = document.createElement("a");
      a.href = `#slide-${i}`;
      if (isChapterHead(i)) a.classList.add("toc-chapter");
      a.innerHTML =
        `<span class="toc-num">${String(i + 1).padStart(2, "0")}</span>` +
        `<span class="toc-title"></span>`;
      // タイトルはtextContentで安全に挿入（HTMLインジェクション防止）
      a.querySelector(".toc-title").textContent = title;
      a.addEventListener("click", (e) => {
        e.preventDefault();
        goTo(i);
        closeToc();
      });
      li.appendChild(a);
      tocList.appendChild(li);
    });
  }

  // ---- TOCモーダルの開閉 ---------------------------------------------
  function openToc() {
    if (tocModal) tocModal.classList.add("show");
  }
  function closeToc() {
    if (tocModal) tocModal.classList.remove("show");
  }
  function tocIsOpen() {
    return tocModal ? tocModal.classList.contains("show") : false;
  }

  if (tocBtn) {
    tocBtn.addEventListener("click", () => {
      if (tocIsOpen()) closeToc();
      else openToc();
    });
  }
  if (tocModal) {
    // 背景（モーダル本体）クリックで閉じる。中身クリックでは閉じない。
    tocModal.addEventListener("click", (e) => {
      if (e.target === tocModal) closeToc();
    });
  }

  // ---- 現在スライドの追跡（スクロール連動） --------------------------
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting && entry.intersectionRatio >= 0.5) {
          const idx = slides.indexOf(entry.target);
          if (idx < 0) return;
          current = idx;
          if (curNumEl) curNumEl.textContent = String(idx + 1).padStart(2, "0");
          if (prevBtn) prevBtn.disabled = idx === 0;
          if (nextBtn) nextBtn.disabled = idx === total - 1;
        }
      });
    },
    { threshold: [0.5] }
  );
  slides.forEach((s) => observer.observe(s));

  // ---- 前へ / 次へ ボタン --------------------------------------------
  if (prevBtn) {
    prevBtn.addEventListener("click", () => goTo(current - 1));
    prevBtn.disabled = true; // 初期状態は先頭なので「前へ」は無効
  }
  if (nextBtn) {
    nextBtn.addEventListener("click", () => goTo(current + 1));
    nextBtn.disabled = total <= 1;
  }

  // ---- キーボード操作 ------------------------------------------------
  document.addEventListener("keydown", (e) => {
    // 目次が開いているときは Esc で閉じるだけ
    if (tocIsOpen()) {
      if (e.key === "Escape") closeToc();
      return;
    }
    switch (e.key) {
      case "ArrowDown":
      case "ArrowRight":
      case "PageDown":
      case " ": // スペースキー
        e.preventDefault();
        goTo(current + 1);
        break;
      case "ArrowUp":
      case "ArrowLeft":
      case "PageUp":
        e.preventDefault();
        goTo(current - 1);
        break;
      case "Home":
        e.preventDefault();
        goTo(0);
        break;
      case "End":
        e.preventDefault();
        goTo(total - 1);
        break;
    }
  });

  // ---- スワイプ操作（スマホ） ----------------------------------------
  // 縦フリックでスライドを移動。一定距離以上動いたときだけ反応させる。
  const SWIPE_THRESHOLD = 60; // px
  let touchStartY = 0;
  let touchStartX = 0;
  let touching = false;

  document.addEventListener(
    "touchstart",
    (e) => {
      if (e.touches.length !== 1) return;
      touchStartY = e.touches[0].clientY;
      touchStartX = e.touches[0].clientX;
      touching = true;
    },
    { passive: true }
  );

  document.addEventListener(
    "touchend",
    (e) => {
      if (!touching) return;
      touching = false;
      const t = e.changedTouches[0];
      const dy = t.clientY - touchStartY;
      const dx = t.clientX - touchStartX;
      // 横移動が大きいスワイプは無視（ブラウザの戻る等と競合させない）
      if (Math.abs(dy) < SWIPE_THRESHOLD || Math.abs(dx) > Math.abs(dy)) return;
      if (dy < 0) goTo(current + 1); // 上にフリック → 次へ
      else goTo(current - 1); // 下にフリック → 前へ
    },
    { passive: true }
  );
})();
