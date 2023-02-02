function readMore(info) {
    let dots = document.querySelector(`.card[data1="${info}"] .dots`);
    let moreText = document.querySelector(`.card[data1="${info}"] .more`);
    let btnText = document.querySelector(`.card[data1="${info}"] .big-btn`);

    if (dots.style.display === "none") {
        dots.style.display = "inline";
        btnText.textContent = "Read more";
        moreText.style.display = "none";
    } else {
        dots.style.display = "none";
        btnText.textContent = "Read less";
        moreText.style.display = "inline";
    }
}