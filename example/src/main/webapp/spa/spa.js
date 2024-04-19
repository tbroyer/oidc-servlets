const heading = document.createElement("h1");
const list = document.createElement("ul");
list.innerHTML = `<li><a href="/">Go to home</a>`;
if (user.admin) {
    list.insertAdjacentHTML("beforeend", `<li><a href="/admin/">Go to admin</a>`);
}
const paragraph = document.createElement("p");
paragraph.append(user.name);
document.body.append(heading, list, paragraph);
paragraph.insertAdjacentHTML("afterend", `<form method=post action=/logout><button type=submit>Logout</button></form>`);

const listItem = document.createElement("li");
const link = document.createElement("a");
listItem.append(link);
list.append(listItem);

function updatePage() {
    if (location.pathname === "/spa/" || location.pathname === "/spa/index.jsp") {
        document.title = heading.textContent = "SPA";
        link.textContent = "Go to other page";
        link.href = "/spa/other";
    } else {
        const page = window.location.pathname.replace(/^\/spa\//, '');
        document.title = heading.textContent = `SPA: ${page}`;
        link.textContent = "Go to SPA home"
        link.href = "/spa/";
    }
}

link.addEventListener('click', e => {
    e.preventDefault();
    history.pushState(null, null, link.href);
    updatePage();
});
window.addEventListener('popstate', updatePage);

updatePage();
