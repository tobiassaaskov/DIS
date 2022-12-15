document.addEventListener("DOMContentLoaded", (event) => {
fetch("http://localhost:3000/authenticate")
      .then(res => res.json())
      .then(data => console.log(data))
      
      .catch((err) => {
        // her "fanger" vi eventuelle fejl
        window.alert(err); // hvis noget går galt, fortæller vi brugeren, at noget er gået galt via en window alert
});
});
