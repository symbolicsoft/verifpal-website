let navToggleLoad = () => {
	let toggle = document.querySelector('.navToggle')
	let links = document.querySelector('.navLinks')
	if (!toggle || !links) return
	toggle.addEventListener('click', () => {
		links.classList.toggle('open')
	})
	links.querySelectorAll('a').forEach((a) => {
		a.addEventListener('click', () => {
			links.classList.remove('open')
		})
	})
}

let footerYearLoad = () => {
	let f = document.getElementById('footerYear')
	if (f) f.innerText = (new Date()).getFullYear()
}

let highlightLoad = () => {
	document.querySelectorAll('code').forEach((block) => {
		hljs.highlightBlock(block)
	})
}

let latestReleaseLoad = () => {
	let d = document.getElementById('latestRelease')
	if (!d) return
	let tagsUri = 'https://api.github.com/repos/symbolicsoft/verifpal/tags'
	fetch(tagsUri)
		.then((r) => r.json())
		.then((data) => {
			if (data[0]) d.innerText = data[0].name
		})
		.catch(() => {})
}

let init = (funcs) => {
	window.addEventListener('DOMContentLoaded', () => {
		funcs.forEach((f) => f())
	})
}