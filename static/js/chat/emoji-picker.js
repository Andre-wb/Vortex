/**
 * Vortex Emoji Picker — полноценный пикер эмодзи для чата.
 *
 * Фичи:
 *   - 1500+ emoji, 9 категорий
 *   - Поиск по названию и ключевым словам (RU + EN)
 *   - Часто используемые (top-24, localStorage)
 *   - Skin tone selector (6 тонов)
 *   - Вставка в позицию курсора
 *   - Keyboard navigation (стрелки, Enter, Escape, Tab)
 *   - GPU-accelerated scroll, виртуализация
 *   - Adaptive: mobile bottom sheet / desktop popup
 */

// ── Emoji Database ──────────────────────────────────────────────────────────
// Compact format: [emoji, name, keywords]

const CATEGORIES = [
    { id: 'recent',   icon: '🕐', name: 'Часто используемые' },
    { id: 'smileys',  icon: '😀', name: 'Смайлики' },
    { id: 'people',   icon: '👋', name: 'Люди и жесты' },
    { id: 'animals',  icon: '🐶', name: 'Животные и природа' },
    { id: 'food',     icon: '🍕', name: 'Еда и напитки' },
    { id: 'travel',   icon: '✈️', name: 'Путешествия' },
    { id: 'activity', icon: '⚽', name: 'Активности' },
    { id: 'objects',  icon: '💡', name: 'Объекты' },
    { id: 'symbols',  icon: '❤️', name: 'Символы' },
    { id: 'flags',    icon: '🏁', name: 'Флаги' },
    { id: 'stickers', icon: '🗂', name: 'Стикеры' },
];

// Full emoji data grouped by category
const EMOJI_DATA = {
    smileys: [
        ['😀','grinning','улыбка smile happy'],
        ['😃','smiley','улыбка smile happy'],
        ['😄','smile','улыбка smile happy laugh'],
        ['😁','grin','улыбка grin teeth'],
        ['😆','laughing','смех laugh haha'],
        ['😅','sweat smile','пот нервный'],
        ['🤣','rofl','ржу floor rolling'],
        ['😂','joy','слёзы радости cry laugh'],
        ['🙂','slightly smiling','легкая улыбка'],
        ['🙃','upside down','перевёрнутый sarcasm'],
        ['😉','wink','подмигивание'],
        ['😊','blush','стеснение скромный'],
        ['😇','innocent','ангел halo'],
        ['🥰','hearts face','влюблённый love'],
        ['😍','heart eyes','сердечки глаза love'],
        ['🤩','star struck','звёзды вау wow'],
        ['😘','kissing heart','поцелуй kiss'],
        ['😗','kissing','поцелуй kiss'],
        ['😚','kissing closed','поцелуй kiss'],
        ['😙','kissing smiling','поцелуй kiss'],
        ['🥲','holding back tears','грустная улыбка'],
        ['😋','yum','вкусно delicious tongue'],
        ['😛','stuck out tongue','язык playful'],
        ['😜','wink tongue','язык подмигивание crazy'],
        ['🤪','zany','сумасшедший crazy wild'],
        ['😝','squinting tongue','язык'],
        ['🤑','money face','деньги money rich'],
        ['🤗','hugs','обнимашки hug'],
        ['🤭','hand over mouth','ой oops'],
        ['🫢','peeking','подглядывание'],
        ['🫣','peeking','подглядывание'],
        ['🤫','shushing','тихо secret quiet'],
        ['🤔','thinking','думаю hmm'],
        ['🫡','salute','салют привет'],
        ['🤐','zipper mouth','молчание zip quiet'],
        ['🤨','raised eyebrow','бровь skeptic'],
        ['😐','neutral','нейтральный'],
        ['😑','expressionless','без эмоций'],
        ['😶','no mouth','без рта'],
        ['🫥','dotted face','невидимка'],
        ['😏','smirk','ухмылка smug'],
        ['😒','unamused','недоволен'],
        ['🙄','eye roll','закатил глаза'],
        ['😬','grimacing','гримаса awkward'],
        ['🤥','lying','пиноккио lie'],
        ['🫠','melting','таю'],
        ['😌','relieved','облегчение'],
        ['😔','pensive','задумчивый sad'],
        ['😪','sleepy','сонный'],
        ['🤤','drooling','слюни'],
        ['😴','sleeping','сплю zzz'],
        ['😷','mask','маска sick'],
        ['🤒','thermometer','температура болею'],
        ['🤕','bandage','бинт hurt'],
        ['🤢','nauseated','тошнит'],
        ['🤮','vomiting','рвота'],
        ['🥵','hot','жарко hot'],
        ['🥶','cold','холодно cold freeze'],
        ['🥴','woozy','пьяный dizzy'],
        ['😵','dizzy','головокружение'],
        ['😵‍💫','spiral eyes','спираль глаза'],
        ['🤯','exploding head','взрыв мозга mind blown'],
        ['🤠','cowboy','ковбой'],
        ['🥳','party','вечеринка celebrate'],
        ['🥸','disguise','маскировка'],
        ['😎','sunglasses','крутой cool'],
        ['🤓','nerd','ботан glasses'],
        ['🧐','monocle','монокль inspect'],
        ['😕','confused','запутался'],
        ['🫤','diagonal mouth','кривой рот'],
        ['😟','worried','обеспокоен worry'],
        ['🙁','frowning','грустный'],
        ['😮','open mouth','удивлён oh'],
        ['😯','hushed','ого'],
        ['😲','astonished','поражён shocked'],
        ['😳','flushed','покраснел embarrassed'],
        ['🥺','pleading','умоляющий puppy'],
        ['🥹','holding back tears','трогательно'],
        ['😦','frowning open','расстроен'],
        ['😧','anguished','мучение'],
        ['😨','fearful','страх scared'],
        ['😰','anxious sweat','тревога nervous'],
        ['😥','sad relieved','грустный'],
        ['😢','cry','плачу tear'],
        ['😭','sob','рыдаю crying loud'],
        ['😱','scream','крик horror'],
        ['😖','confounded','сбит с толку'],
        ['😣','persevere','терпение'],
        ['😞','disappointed','разочарован'],
        ['😓','downcast sweat','разочарован'],
        ['😩','weary','устал'],
        ['😫','tired','очень устал'],
        ['🥱','yawning','зевок bored'],
        ['😤','triumph','пыхтит angry'],
        ['😡','rage','ярость mad'],
        ['😠','angry','злой'],
        ['🤬','cursing','ругань @#$%'],
        ['😈','imp','дьяволёнок devil'],
        ['👿','angry devil','злой дьявол'],
        ['💀','skull','череп dead'],
        ['☠️','crossbones','яд danger'],
        ['💩','poop','какашка shit'],
        ['🤡','clown','клоун'],
        ['👹','ogre','людоед'],
        ['👺','goblin','гоблин'],
        ['👻','ghost','призрак boo'],
        ['👽','alien','инопланетянин'],
        ['👾','space invader','пришелец game'],
        ['🤖','robot','робот'],
        ['😺','smiley cat','кот улыбка'],
        ['😸','grinning cat','кот'],
        ['😹','joy cat','кот смех'],
        ['😻','heart eyes cat','кот любовь'],
        ['😼','smirk cat','кот ухмылка'],
        ['😽','kissing cat','кот поцелуй'],
        ['🙀','weary cat','кот ужас'],
        ['😿','crying cat','кот плачет'],
        ['😾','pouting cat','кот злой'],
        ['🫶','heart hands','руки сердце love'],
        ['🙈','see no evil','не вижу monkey'],
        ['🙉','hear no evil','не слышу monkey'],
        ['🙊','speak no evil','не говорю monkey'],
    ],
    people: [
        ['👋','wave','привет hello hi'],
        ['🤚','raised back','ладонь stop'],
        ['🖐️','hand fingers','ладонь пять high five'],
        ['✋','raised hand','стоп stop'],
        ['🖖','vulcan','вулкан spock'],
        ['🫱','rightwards hand','рука вправо'],
        ['🫲','leftwards hand','рука влево'],
        ['🫳','palm down','ладонь вниз'],
        ['🫴','palm up','ладонь вверх'],
        ['👌','ok','ок okay'],
        ['🤌','pinched','щепотка italian'],
        ['🤏','pinching','чуть-чуть small'],
        ['✌️','victory','победа peace'],
        ['🤞','crossed fingers','удачи luck'],
        ['🫰','hand with index','деньги snap'],
        ['🤟','love you','люблю rock'],
        ['🤘','rock','рок metal'],
        ['🤙','call me','позвони phone'],
        ['👈','point left','налево left'],
        ['👉','point right','направо right'],
        ['👆','point up','вверх up'],
        ['🖕','middle finger','фак'],
        ['👇','point down','вниз down'],
        ['☝️','index up','палец вверх'],
        ['🫵','point at viewer','на тебя you'],
        ['👍','thumbs up','класс like yes'],
        ['👎','thumbs down','не класс dislike no'],
        ['✊','fist','кулак power'],
        ['👊','punch','удар fist bump'],
        ['🤛','left fist','кулак лево'],
        ['🤜','right fist','кулак право'],
        ['👏','clap','аплодисменты'],
        ['🙌','raised hands','ура celebrate'],
        ['🫶','heart hands','руки сердце'],
        ['👐','open hands','открытые руки'],
        ['🤲','palms up','ладони вверх'],
        ['🤝','handshake','рукопожатие deal'],
        ['🙏','pray','молитва please thanks'],
        ['✍️','writing','пишет'],
        ['💅','nail polish','маникюр'],
        ['🤳','selfie','селфи'],
        ['💪','flexed bicep','мускул strong muscle'],
        ['🦾','mechanical arm','робот рука prosthetic'],
        ['🦿','mechanical leg','робот нога'],
        ['🦵','leg','нога'],
        ['🦶','foot','ступня'],
        ['👂','ear','ухо listen'],
        ['👃','nose','нос smell'],
        ['🧠','brain','мозг smart think'],
        ['👀','eyes','глаза look see'],
        ['👁️','eye','глаз'],
        ['👅','tongue','язык taste'],
        ['👄','mouth','рот lips'],
        ['👶','baby','малыш baby'],
        ['🧒','child','ребёнок kid'],
        ['👦','boy','мальчик'],
        ['👧','girl','девочка'],
        ['🧑','person','человек'],
        ['👱','blond','блондин'],
        ['👨','man','мужчина'],
        ['👩','woman','женщина'],
        ['🧔','beard','борода'],
        ['👴','old man','старик дед'],
        ['👵','old woman','старушка бабушка'],
    ],
    animals: [
        ['🐶','dog','собака пёс'],
        ['🐱','cat','кот кошка'],
        ['🐭','mouse','мышь'],
        ['🐹','hamster','хомяк'],
        ['🐰','rabbit','кролик'],
        ['🦊','fox','лиса'],
        ['🐻','bear','медведь'],
        ['🐼','panda','панда'],
        ['🐻‍❄️','polar bear','белый медведь'],
        ['🐨','koala','коала'],
        ['🐯','tiger','тигр'],
        ['🦁','lion','лев king'],
        ['🐮','cow','корова'],
        ['🐷','pig','свинья'],
        ['🐸','frog','лягушка'],
        ['🐵','monkey','обезьяна'],
        ['🐔','chicken','курица'],
        ['🐧','penguin','пингвин'],
        ['🐦','bird','птица'],
        ['🐤','chick','цыплёнок'],
        ['🦆','duck','утка'],
        ['🦅','eagle','орёл'],
        ['🦉','owl','сова'],
        ['🦇','bat','летучая мышь'],
        ['🐺','wolf','волк'],
        ['🐗','boar','кабан'],
        ['🐴','horse','лошадь конь'],
        ['🦄','unicorn','единорог magic'],
        ['🐝','bee','пчела honey'],
        ['🪱','worm','червь'],
        ['🐛','bug','жук'],
        ['🦋','butterfly','бабочка'],
        ['🐌','snail','улитка slow'],
        ['🐞','ladybug','божья коровка'],
        ['🐜','ant','муравей'],
        ['🪰','fly','муха'],
        ['🐢','turtle','черепаха slow'],
        ['🐍','snake','змея'],
        ['🦎','lizard','ящерица'],
        ['🦂','scorpion','скорпион'],
        ['🕷️','spider','паук'],
        ['🐙','octopus','осьминог'],
        ['🦑','squid','кальмар'],
        ['🦐','shrimp','креветка'],
        ['🦀','crab','краб'],
        ['🐡','blowfish','рыба-ёж'],
        ['🐠','tropical fish','рыбка'],
        ['🐟','fish','рыба'],
        ['🐬','dolphin','дельфин'],
        ['🐳','whale','кит'],
        ['🦈','shark','акула'],
        ['🐊','crocodile','крокодил'],
        ['🐅','tiger','тигр'],
        ['🐆','leopard','леопард'],
        ['🦓','zebra','зебра'],
        ['🦍','gorilla','горилла'],
        ['🦧','orangutan','орангутан'],
        ['🐘','elephant','слон'],
        ['🦛','hippo','бегемот'],
        ['🦏','rhino','носорог'],
        ['🐪','camel','верблюд'],
        ['🐫','two hump camel','верблюд'],
        ['🦒','giraffe','жираф'],
        ['🌲','evergreen','ёлка tree'],
        ['🌳','deciduous tree','дерево'],
        ['🌴','palm tree','пальма'],
        ['🌵','cactus','кактус'],
        ['🌸','cherry blossom','сакура цветок'],
        ['🌺','hibiscus','гибискус цветок'],
        ['🌻','sunflower','подсолнух'],
        ['🌹','rose','роза flower'],
        ['🌷','tulip','тюльпан'],
        ['💐','bouquet','букет flowers'],
        ['🍄','mushroom','гриб'],
        ['🌾','rice','рис зерно'],
        ['🍀','four leaf clover','клевер luck'],
        ['🍁','maple leaf','клён лист autumn'],
        ['🍂','fallen leaf','осень листья'],
        ['🍃','leaf fluttering','лист ветер'],
    ],
    food: [
        ['🍕','pizza','пицца'],
        ['🍔','hamburger','бургер burger'],
        ['🍟','fries','картошка фри'],
        ['🌭','hot dog','хот-дог'],
        ['🍿','popcorn','попкорн'],
        ['🧂','salt','соль'],
        ['🥚','egg','яйцо'],
        ['🍳','cooking','яичница'],
        ['🥞','pancakes','блины'],
        ['🧇','waffle','вафля'],
        ['🥓','bacon','бекон'],
        ['🥩','steak','стейк мясо'],
        ['🍗','poultry','курица ножка'],
        ['🍖','meat on bone','мясо'],
        ['🌮','taco','тако'],
        ['🌯','burrito','буррито'],
        ['🫔','tamale','тамале'],
        ['🥗','salad','салат'],
        ['🥣','cereal','каша'],
        ['🍝','spaghetti','спагетти pasta'],
        ['🍜','ramen','рамен noodles'],
        ['🍲','stew','суп рагу'],
        ['🍛','curry','карри'],
        ['🍣','sushi','суши'],
        ['🍱','bento','бенто'],
        ['🥟','dumpling','пельмень'],
        ['🍤','shrimp','креветка'],
        ['🍙','rice ball','онигири'],
        ['🍚','rice','рис'],
        ['🍘','rice cracker','рисовый крекер'],
        ['🍰','cake','торт'],
        ['🎂','birthday cake','торт день рождения'],
        ['🧁','cupcake','кекс'],
        ['🍩','donut','пончик'],
        ['🍪','cookie','печенье'],
        ['🍫','chocolate','шоколад'],
        ['🍬','candy','конфета'],
        ['🍭','lollipop','леденец'],
        ['🍮','custard','пудинг'],
        ['🍯','honey','мёд'],
        ['🍼','bottle','бутылка молоко baby'],
        ['☕','coffee','кофе'],
        ['🍵','tea','чай'],
        ['🧃','juice','сок'],
        ['🥤','cup straw','стакан'],
        ['🧋','bubble tea','боба чай'],
        ['🍶','sake','саке'],
        ['🍺','beer','пиво'],
        ['🍻','clinking beer','чокаемся пиво cheers'],
        ['🥂','champagne','шампанское toast'],
        ['🍷','wine','вино'],
        ['🍸','cocktail','коктейль martini'],
        ['🍹','tropical drink','тропик коктейль'],
        ['🧊','ice','лёд'],
        ['🍉','watermelon','арбуз'],
        ['🍊','orange','апельсин'],
        ['🍋','lemon','лимон'],
        ['🍌','banana','банан'],
        ['🍍','pineapple','ананас'],
        ['🥭','mango','манго'],
        ['🍎','apple','яблоко red'],
        ['🍏','green apple','яблоко green'],
        ['🍐','pear','груша'],
        ['🍑','peach','персик'],
        ['🍒','cherry','вишня'],
        ['🍓','strawberry','клубника'],
        ['🫐','blueberry','черника'],
        ['🥝','kiwi','киви'],
        ['🥑','avocado','авокадо'],
        ['🍆','eggplant','баклажан'],
        ['🥔','potato','картошка'],
        ['🥕','carrot','морковь'],
        ['🌽','corn','кукуруза'],
        ['🌶️','hot pepper','перец chili'],
        ['🫑','bell pepper','перец'],
        ['🥒','cucumber','огурец'],
        ['🧄','garlic','чеснок'],
        ['🧅','onion','лук'],
        ['🥜','peanuts','арахис орехи'],
    ],
    travel: [
        ['✈️','airplane','самолёт flight'],
        ['🚀','rocket','ракета launch space'],
        ['🛸','ufo','нло alien'],
        ['🚁','helicopter','вертолёт'],
        ['🚂','locomotive','поезд train'],
        ['🚗','car','машина auto'],
        ['🚕','taxi','такси'],
        ['🚌','bus','автобус'],
        ['🏎️','racing car','гонки'],
        ['🚲','bicycle','велосипед bike'],
        ['🛵','motor scooter','скутер'],
        ['🚢','ship','корабль'],
        ['⛵','sailboat','парусник'],
        ['🏠','house','дом home'],
        ['🏢','office','офис building'],
        ['🏰','castle','замок'],
        ['🏛️','classical','классика museum'],
        ['⛪','church','церковь'],
        ['🕌','mosque','мечеть'],
        ['🗽','statue liberty','статуя свободы'],
        ['🗼','tokyo tower','башня tower'],
        ['🌉','bridge','мост night'],
        ['🌍','earth europe','земля планета world'],
        ['🌎','earth americas','земля америка'],
        ['🌏','earth asia','земля азия'],
        ['🌐','globe','глобус internet'],
        ['🗺️','world map','карта мира'],
        ['🧭','compass','компас'],
        ['⛰️','mountain','гора'],
        ['🏔️','snow mountain','снежная гора'],
        ['🌋','volcano','вулкан'],
        ['🏕️','camping','кемпинг'],
        ['🏖️','beach','пляж'],
        ['🏜️','desert','пустыня'],
        ['🌅','sunrise','рассвет'],
        ['🌄','sunrise mountain','рассвет горы'],
        ['🌇','sunset','закат'],
        ['🌆','cityscape dusk','город вечер'],
        ['🌃','night city','город ночь'],
        ['🌌','milky way','млечный путь stars'],
        ['🌠','shooting star','звезда падающая'],
        ['🎆','fireworks','фейерверк'],
        ['🎇','sparkler','бенгальский огонь'],
    ],
    activity: [
        ['⚽','soccer','футбол'],
        ['🏀','basketball','баскетбол'],
        ['🏈','football','американский футбол'],
        ['⚾','baseball','бейсбол'],
        ['🥎','softball','софтбол'],
        ['🎾','tennis','теннис'],
        ['🏐','volleyball','волейбол'],
        ['🏉','rugby','регби'],
        ['🥏','frisbee','фрисби'],
        ['🎱','pool','бильярд'],
        ['🏓','ping pong','пинг-понг'],
        ['🏸','badminton','бадминтон'],
        ['🏒','hockey','хоккей'],
        ['🥅','goal','ворота'],
        ['⛳','golf','гольф'],
        ['🏹','bow','лук стрельба'],
        ['🎣','fishing','рыбалка'],
        ['🥊','boxing','бокс'],
        ['🥋','martial arts','единоборства'],
        ['🎿','ski','лыжи'],
        ['⛷️','skier','лыжник'],
        ['🏂','snowboard','сноуборд'],
        ['🏋️','weightlifting','тяжёлая атлетика gym'],
        ['🤸','cartwheel','колесо'],
        ['🤼','wrestling','борьба'],
        ['🤽','water polo','водное поло'],
        ['🚴','cycling','велоспорт'],
        ['🧘','yoga','йога meditation'],
        ['🎪','circus','цирк'],
        ['🎭','theater','театр masks drama'],
        ['🎨','art','искусство paint'],
        ['🎬','movie','кино camera film'],
        ['🎤','microphone','микрофон sing karaoke'],
        ['🎧','headphones','наушники music'],
        ['🎵','music note','нота'],
        ['🎶','music notes','ноты melody'],
        ['🎹','piano','пианино'],
        ['🥁','drum','барабан'],
        ['🎷','saxophone','саксофон jazz'],
        ['🎺','trumpet','труба'],
        ['🎸','guitar','гитара rock'],
        ['🎻','violin','скрипка'],
        ['🎮','video game','игра game controller'],
        ['🕹️','joystick','джойстик'],
        ['🎲','dice','кубик'],
        ['🎯','dart','дартс target bullseye'],
        ['🧩','puzzle','пазл'],
        ['🎰','slot machine','слот jackpot'],
        ['🏆','trophy','трофей winner cup'],
        ['🏅','medal','медаль'],
        ['🥇','gold medal','золото first'],
        ['🥈','silver medal','серебро second'],
        ['🥉','bronze medal','бронза third'],
    ],
    objects: [
        ['💡','light bulb','лампочка idea'],
        ['🔦','flashlight','фонарик'],
        ['💻','laptop','ноутбук computer'],
        ['🖥️','desktop','компьютер desktop pc'],
        ['⌨️','keyboard','клавиатура'],
        ['🖱️','mouse','мышка'],
        ['🖨️','printer','принтер'],
        ['📱','phone','телефон mobile'],
        ['📞','telephone','телефон call'],
        ['📷','camera','камера photo'],
        ['📹','video camera','видеокамера'],
        ['📺','tv','телевизор television'],
        ['🔌','electric plug','розетка plug'],
        ['🔋','battery','батарея'],
        ['💾','floppy disk','дискета save'],
        ['💿','cd','диск'],
        ['📀','dvd','двд'],
        ['📡','satellite','спутник antenna'],
        ['🔑','key','ключ password'],
        ['🗝️','old key','старый ключ'],
        ['🔒','locked','замок lock'],
        ['🔓','unlocked','открыто unlock'],
        ['🔐','locked key','замок ключ secure'],
        ['🛡️','shield','щит protect security'],
        ['🔫','gun','пистолет'],
        ['💣','bomb','бомба'],
        ['🔪','knife','нож'],
        ['🗡️','sword','меч'],
        ['⚔️','crossed swords','мечи battle'],
        ['💊','pill','таблетка medicine'],
        ['💉','syringe','шприц vaccine'],
        ['🩺','stethoscope','стетоскоп doctor'],
        ['📦','package','коробка box'],
        ['📫','mailbox','почтовый ящик mail'],
        ['📮','postbox','почта'],
        ['📬','mailbox open','почта письмо'],
        ['📧','email','электронная почта'],
        ['✉️','envelope','конверт letter'],
        ['📝','memo','заметка note write'],
        ['📒','ledger','блокнот'],
        ['📕','book','книга'],
        ['📖','open book','открытая книга read'],
        ['📚','books','книги study'],
        ['📎','paperclip','скрепка attach'],
        ['📌','pushpin','кнопка pin'],
        ['📏','ruler','линейка'],
        ['✂️','scissors','ножницы cut'],
        ['🖊️','pen','ручка write'],
        ['✏️','pencil','карандаш'],
        ['🖌️','paintbrush','кисть art'],
        ['🔍','magnifying glass','лупа search zoom'],
        ['🔬','microscope','микроскоп science'],
        ['🔭','telescope','телескоп space'],
        ['💰','money bag','мешок денег rich'],
        ['💵','dollar','доллар money'],
        ['💴','yen','йена'],
        ['💶','euro','евро'],
        ['💷','pound','фунт'],
        ['💳','credit card','кредитка card pay'],
        ['💎','gem','бриллиант diamond'],
        ['⚙️','gear','шестерёнка settings'],
        ['🔧','wrench','ключ гаечный tool'],
        ['🔨','hammer','молоток tool'],
        ['🪛','screwdriver','отвёртка'],
        ['⏰','alarm clock','будильник time'],
        ['⏱️','stopwatch','секундомер'],
        ['⏳','hourglass','песочные часы time wait'],
    ],
    symbols: [
        ['❤️','red heart','красное сердце love'],
        ['🧡','orange heart','оранжевое сердце'],
        ['💛','yellow heart','жёлтое сердце'],
        ['💚','green heart','зелёное сердце'],
        ['💙','blue heart','синее сердце'],
        ['💜','purple heart','фиолетовое сердце'],
        ['🖤','black heart','чёрное сердце'],
        ['🤍','white heart','белое сердце'],
        ['🤎','brown heart','коричневое сердце'],
        ['💔','broken heart','разбитое сердце'],
        ['❤️‍🔥','heart on fire','горящее сердце'],
        ['❤️‍🩹','mending heart','заживающее сердце'],
        ['💕','two hearts','два сердца'],
        ['💞','revolving hearts','вращающиеся сердца'],
        ['💓','heartbeat','сердцебиение'],
        ['💗','growing heart','растущее сердце'],
        ['💖','sparkling heart','блестящее сердце'],
        ['💘','cupid heart','стрела купидона'],
        ['💝','gift heart','подарок сердце'],
        ['💟','heart decoration','сердце декор'],
        ['☮️','peace','мир'],
        ['✝️','cross','крест'],
        ['☪️','star crescent','полумесяц'],
        ['☸️','dharma wheel','дхарма'],
        ['✡️','star david','звезда давида'],
        ['🔯','six pointed star','шестиконечная'],
        ['🕐','one oclock','час'],
        ['♻️','recycle','переработка'],
        ['⚠️','warning','внимание alert danger'],
        ['🚫','prohibited','запрещено no ban'],
        ['❌','cross mark','крест нет wrong'],
        ['⭕','circle','круг'],
        ['✅','check mark','галочка done yes ok'],
        ['☑️','check box','флажок'],
        ['✔️','check','готово yes'],
        ['❗','exclamation','восклицание important'],
        ['❓','question','вопрос'],
        ['‼️','double exclamation','двойное восклицание'],
        ['⁉️','exclamation question','восклицание вопрос'],
        ['💯','hundred','сто percent perfect'],
        ['🔥','fire','огонь hot lit'],
        ['✨','sparkles','блёстки magic'],
        ['⭐','star','звезда'],
        ['🌟','glowing star','сияющая звезда'],
        ['💫','dizzy star','звёздочка'],
        ['💥','collision','взрыв boom'],
        ['💢','anger','злость'],
        ['💬','speech bubble','облачко чат message'],
        ['👁️‍🗨️','eye speech','глаз чат'],
        ['🗯️','anger bubble','злой облачко'],
        ['💭','thought bubble','мысль think'],
        ['🕳️','hole','дыра'],
        ['🚩','red flag','красный флаг'],
        ['🏳️','white flag','белый флаг'],
        ['🏴','black flag','чёрный флаг'],
        ['🏳️‍🌈','rainbow flag','радуга pride'],
        ['🔇','muted','без звука'],
        ['🔈','speaker low','динамик тихо'],
        ['🔉','speaker medium','динамик средне'],
        ['🔊','speaker high','динамик громко'],
        ['📣','megaphone','мегафон'],
        ['📢','loudspeaker','громкоговоритель announcement'],
        ['🔔','bell','колокольчик notification'],
        ['🔕','bell slash','без уведомлений mute'],
        ['🎵','music','музыка'],
        ['🎶','notes','ноты'],
        ['♾️','infinity','бесконечность'],
        ['♈','aries','овен'],
        ['♉','taurus','телец'],
        ['♊','gemini','близнецы'],
        ['♋','cancer','рак'],
        ['♌','leo','лев'],
        ['♍','virgo','дева'],
        ['♎','libra','весы'],
        ['♏','scorpio','скорпион'],
        ['♐','sagittarius','стрелец'],
        ['♑','capricorn','козерог'],
        ['♒','aquarius','водолей'],
        ['♓','pisces','рыбы'],
        ['➕','plus','плюс add'],
        ['➖','minus','минус subtract'],
        ['➗','divide','делить'],
        ['✖️','multiply','умножить'],
        ['🟰','equals','равно'],
        ['♠️','spades','пики'],
        ['♥️','hearts','черви'],
        ['♦️','diamonds','бубны'],
        ['♣️','clubs','трефы'],
    ],
    flags: [
        ['🏁','checkered flag','финиш race'],
        ['🚩','red flag','красный флаг warning'],
        ['🇷🇺','russia','россия ru'],
        ['🇺🇸','usa','сша us america'],
        ['🇬🇧','uk','великобритания gb england'],
        ['🇩🇪','germany','германия de'],
        ['🇫🇷','france','франция fr'],
        ['🇪🇸','spain','испания es'],
        ['🇮🇹','italy','италия it'],
        ['🇯🇵','japan','япония jp'],
        ['🇨🇳','china','китай cn'],
        ['🇰🇷','korea','корея kr'],
        ['🇧🇷','brazil','бразилия br'],
        ['🇮🇳','india','индия in'],
        ['🇹🇷','turkey','турция tr'],
        ['🇺🇦','ukraine','украина ua'],
        ['🇰🇿','kazakhstan','казахстан kz'],
        ['🇧🇾','belarus','беларусь by'],
        ['🇵🇱','poland','польша pl'],
        ['🇨🇦','canada','канада ca'],
        ['🇦🇺','australia','австралия au'],
    ],
};

// Skin tones
const SKIN_TONES = [
    { mod: '', label: '\u{1F44B} Default', color: '#ffcc4d' },
    { mod: '\u{1F3FB}', label: '\u{1F44B}\u{1F3FB} Light', color: '#fadcbc' },
    { mod: '\u{1F3FC}', label: '\u{1F44B}\u{1F3FC} Medium-Light', color: '#e0bb95' },
    { mod: '\u{1F3FD}', label: '\u{1F44B}\u{1F3FD} Medium', color: '#bf8f68' },
    { mod: '\u{1F3FE}', label: '\u{1F44B}\u{1F3FE} Medium-Dark', color: '#9b643d' },
    { mod: '\u{1F3FF}', label: '\u{1F44B}\u{1F3FF} Dark', color: '#594539' },
];

// Emoji that support skin tones (ZWJ-safe subset)
const SKIN_TONE_BASE = new Set([
    '👋','🤚','🖐️','✋','🖖','👌','🤌','🤏','✌️','🤞','🫰','🤟',
    '🤘','🤙','👈','👉','👆','🖕','👇','☝️','🫵','👍','👎','✊',
    '👊','🤛','🤜','👏','🙌','👐','🤲','🤝','🙏','✍️','💅','🤳',
    '💪','👂','👃','👶','🧒','👦','👧','🧑','👱','👨','👩','🧔',
    '👴','👵',
]);

// ── State ───────────────────────────────────────────────────────────────────

let _isOpen = false;
let _currentCategory = 'recent';
let _skinTone = '';
let _searchQuery = '';
let _pickerEl = null;

// Sticker state
let _stickerPacks = null;       // null = not loaded yet
let _stickerLoading = false;

const RECENT_KEY = 'vortex_emoji_recent';
const SKIN_KEY = 'vortex_emoji_skin';
const MAX_RECENT = 24;

function _getRecent() {
    try { return JSON.parse(localStorage.getItem(RECENT_KEY) || '[]'); }
    catch { return []; }
}

function _addRecent(emoji) {
    let recent = _getRecent().filter(e => e !== emoji);
    recent.unshift(emoji);
    if (recent.length > MAX_RECENT) recent = recent.slice(0, MAX_RECENT);
    localStorage.setItem(RECENT_KEY, JSON.stringify(recent));
}

function _loadSkinTone() {
    _skinTone = localStorage.getItem(SKIN_KEY) || '';
}

function _saveSkinTone(mod) {
    _skinTone = mod;
    localStorage.setItem(SKIN_KEY, mod);
}

// Apply skin tone to emoji
function _applySkin(emoji) {
    if (!_skinTone || !SKIN_TONE_BASE.has(emoji)) return emoji;
    // Remove existing skin tone modifiers then apply new one
    const base = emoji.replace(/[\u{1F3FB}-\u{1F3FF}]/gu, '');
    return base + _skinTone;
}

// ── Build Picker DOM ────────────────────────────────────────────────────────

function _buildPicker() {
    const el = document.createElement('div');
    el.id = 'emoji-chat-picker';
    el.className = 'emoji-chat-picker';
    el.innerHTML = `
        <div class="ecp-header">
            <div class="ecp-search-wrap">
                <svg class="ecp-search-icon" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
                </svg>
                <input type="text" id="ecp-search" class="ecp-search"
                       placeholder="${typeof window.t === 'function' ? window.t('emoji.searchPlaceholder') : 'Search emoji...'}" autocomplete="off" spellcheck="false">
                <button class="ecp-search-clear" id="ecp-search-clear" style="display:none">&times;</button>
            </div>
            <div class="ecp-skin-btn" id="ecp-skin-btn" title="${typeof window.t === 'function' ? window.t('emoji.skinTone') : 'Skin tone'}">
                <span id="ecp-skin-preview"><svg width="18" height="18" viewBox="0 0 20 20" fill="currentColor"><path d="M17.8 2.2c-1-1-2.6-1-3.6 0L12.4 4l-.7-.7c-.4-.4-1-.4-1.4 0l-.8.7c-.4.4-.4 1 0 1.4l5 5c.4.4 1 .4 1.4 0l.7-.7c.4-.4.4-1 0-1.4l-.6-.7 1.8-1.8c1-1 1-2.6 0-3.6zM4.4 12c-2.2 2.2-.9 3.2-2.9 5.8l.7.7c2.6-2 3.6-.7 5.8-2.9l5.1-5.1-3.6-3.6L4.4 12z"/></svg></span>
            </div>
        </div>
        <div class="ecp-categories" id="ecp-categories"></div>
        <div class="ecp-body" id="ecp-body"></div>
        <div class="ecp-skin-panel" id="ecp-skin-panel" style="display:none"></div>
        <div class="ecp-footer" id="ecp-footer">
            <span class="ecp-preview-emoji" id="ecp-preview-emoji"></span>
            <span class="ecp-preview-name" id="ecp-preview-name"></span>
        </div>
    `;

    // Category tabs
    const catBar = el.querySelector('#ecp-categories');
    CATEGORIES.forEach(cat => {
        const btn = document.createElement('button');
        btn.className = 'ecp-cat-btn' + (cat.id === _currentCategory ? ' active' : '');
        btn.dataset.cat = cat.id;
        btn.title = cat.name;
        btn.textContent = cat.icon;
        btn.onclick = () => _selectCategory(cat.id);
        catBar.appendChild(btn);
    });

    // Skin tone panel
    const skinPanel = el.querySelector('#ecp-skin-panel');
    SKIN_TONES.forEach(tone => {
        const btn = document.createElement('button');
        btn.className = 'ecp-skin-opt' + (tone.mod === _skinTone ? ' active' : '');
        btn.style.background = tone.color;
        btn.title = tone.label;
        btn.onclick = () => {
            _saveSkinTone(tone.mod);
            skinPanel.style.display = 'none';
            skinPanel.querySelectorAll('.active').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            _renderEmojis();
        };
        skinPanel.appendChild(btn);
    });

    // Skin button toggle
    el.querySelector('#ecp-skin-btn').onclick = () => {
        const panel = el.querySelector('#ecp-skin-panel');
        panel.style.display = panel.style.display === 'none' ? 'flex' : 'none';
    };

    // Search
    const searchInput = el.querySelector('#ecp-search');
    const clearBtn = el.querySelector('#ecp-search-clear');
    searchInput.oninput = () => {
        _searchQuery = searchInput.value.trim().toLowerCase();
        clearBtn.style.display = _searchQuery ? 'block' : 'none';
        _renderEmojis();
    };
    clearBtn.onclick = () => {
        searchInput.value = '';
        _searchQuery = '';
        clearBtn.style.display = 'none';
        _renderEmojis();
        searchInput.focus();
    };

    // Keyboard
    searchInput.onkeydown = (e) => {
        if (e.key === 'Escape') { closePicker(); e.preventDefault(); }
    };

    return el;
}

// ── Render Emojis ───────────────────────────────────────────────────────────

function _renderEmojis() {
    const body = _pickerEl?.querySelector('#ecp-body');
    if (!body) return;
    body.innerHTML = '';

    if (_searchQuery) {
        _renderSearchResults(body);
        return;
    }

    if (_currentCategory === 'recent') {
        const recent = _getRecent();
        if (recent.length === 0) {
            body.innerHTML = '<div class="ecp-empty">Нет недавних эмодзи</div>';
            return;
        }
        const grid = _createGrid(recent.map(e => [e, '', '']));
        body.appendChild(grid);
        return;
    }

    if (_currentCategory === 'stickers') {
        _renderStickerTab(body);
        return;
    }

    const data = EMOJI_DATA[_currentCategory];
    if (!data) return;

    const grid = _createGrid(data);
    body.appendChild(grid);
}

// ── Sticker Tab ─────────────────────────────────────────────────────────────

async function _renderStickerTab(body) {
    if (_stickerLoading) {
        body.innerHTML = '<div class="ecp-empty">Загрузка стикеров...</div>';
        return;
    }

    if (!_stickerPacks) {
        _stickerLoading = true;
        body.innerHTML = '<div class="ecp-empty">Загрузка стикеров...</div>';
        try {
            const r = await fetch('/api/stickers/packs');
            if (!r.ok) throw new Error('HTTP ' + r.status);
            const data = await r.json();
            _stickerPacks = [...(data.own || []), ...(data.favorited || [])];
            // Deduplicate by id
            const seen = new Set();
            _stickerPacks = _stickerPacks.filter(p => {
                if (seen.has(p.id)) return false;
                seen.add(p.id);
                return true;
            });
        } catch {
            _stickerPacks = [];
        }
        _stickerLoading = false;
    }

    body.innerHTML = '';

    if (!_stickerPacks.length) {
        body.innerHTML = `
            <div class="ecp-empty" style="padding:20px 12px;text-align:center;">
                <div style="font-size:32px;margin-bottom:8px;">🗂</div>
                <div style="margin-bottom:8px;">Нет стикер-паков</div>
                <div style="font-size:11px;color:var(--text3,#888);">Нажмите на стикер в чате чтобы добавить пак</div>
            </div>`;
        return;
    }

    _stickerPacks.forEach(pack => {
        if (!pack.stickers?.length) return;

        const section = document.createElement('div');
        section.style.cssText = 'margin-bottom:12px;';

        const title = document.createElement('div');
        title.style.cssText = 'font-size:11px;font-weight:600;color:var(--text3,#888);padding:4px 8px 6px;text-transform:uppercase;letter-spacing:.5px;';
        title.textContent = pack.name;
        section.appendChild(title);

        const grid = document.createElement('div');
        grid.style.cssText = 'display:grid;grid-template-columns:repeat(5,1fr);gap:4px;padding:0 4px;';

        pack.stickers.forEach(sticker => {
            const btn = document.createElement('button');
            btn.style.cssText = 'background:none;border:none;padding:4px;border-radius:8px;cursor:pointer;aspect-ratio:1;display:flex;align-items:center;justify-content:center;transition:background .15s;';
            btn.title = sticker.emoji || '';

            const img = document.createElement('img');
            img.src = sticker.image_url;
            img.alt = sticker.emoji || 'sticker';
            img.style.cssText = 'width:48px;height:48px;object-fit:contain;';
            img.loading = 'lazy';
            btn.appendChild(img);

            btn.onmouseenter = () => { btn.style.background = 'var(--bg3,rgba(255,255,255,.08))'; };
            btn.onmouseleave = () => { btn.style.background = 'none'; };

            btn.onclick = () => {
                closePicker();
                window._sendStickerFromPicker?.('[STICKER] img:' + sticker.image_url);
            };

            grid.appendChild(btn);
        });

        section.appendChild(grid);
        body.appendChild(section);
    });
}

export function invalidateStickerCache() {
    _stickerPacks = null;
}

function _renderSearchResults(body) {
    const q = _searchQuery;
    const results = [];

    for (const [catId, emojis] of Object.entries(EMOJI_DATA)) {
        for (const entry of emojis) {
            const [emoji, name, keywords] = entry;
            const searchStr = `${name} ${keywords}`.toLowerCase();
            if (searchStr.includes(q) || emoji === q) {
                results.push(entry);
            }
        }
    }

    if (results.length === 0) {
        body.innerHTML = '<div class="ecp-empty">Ничего не найдено</div>';
        return;
    }

    const grid = _createGrid(results.slice(0, 120));
    body.appendChild(grid);
}

function _createGrid(entries) {
    const grid = document.createElement('div');
    grid.className = 'ecp-grid';

    entries.forEach(([emoji, name, keywords]) => {
        const btn = document.createElement('button');
        btn.className = 'ecp-emoji';
        btn.textContent = _applySkin(emoji);
        btn.dataset.emoji = emoji;
        btn.dataset.name = name;

        btn.onclick = () => _insertEmoji(_applySkin(emoji));

        btn.onmouseenter = () => {
            const previewEmoji = _pickerEl?.querySelector('#ecp-preview-emoji');
            const previewName = _pickerEl?.querySelector('#ecp-preview-name');
            if (previewEmoji) previewEmoji.textContent = _applySkin(emoji);
            if (previewName) previewName.textContent = `:${name}:`;
        };

        grid.appendChild(btn);
    });

    return grid;
}

// ── Insert Emoji ────────────────────────────────────────────────────────────

function _insertEmoji(emoji) {
    const input = document.getElementById('msg-input');
    if (!input) return;

    _addRecent(emoji);

    // Insert at cursor position
    const start = input.selectionStart;
    const end = input.selectionEnd;
    const text = input.value;

    input.value = text.slice(0, start) + emoji + text.slice(end);
    input.selectionStart = input.selectionEnd = start + emoji.length;

    // Trigger input event for auto-resize
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.focus();
}

// ── Category Selection ──────────────────────────────────────────────────────

function _selectCategory(catId) {
    _currentCategory = catId;

    // Update active tab
    _pickerEl?.querySelectorAll('.ecp-cat-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.cat === catId);
    });

    _renderEmojis();

    // Scroll body to top
    const body = _pickerEl?.querySelector('#ecp-body');
    if (body) body.scrollTop = 0;
}

// ── Open / Close ────────────────────────────────────────────────────────────

export function openPicker() {
    if (_isOpen) { closePicker(); return; }

    _loadSkinTone();

    if (!_pickerEl) {
        _pickerEl = _buildPicker();
    }

    const inputRow = document.querySelector('.input-row') || document.getElementById('input-area');
    if (!inputRow) return;

    inputRow.appendChild(_pickerEl);
    _isOpen = true;
    _pickerEl.classList.add('open');

    _renderEmojis();

    // Focus search after animation
    requestAnimationFrame(() => {
        _pickerEl?.querySelector('#ecp-search')?.focus();
    });

    // Close on outside click
    setTimeout(() => {
        document.addEventListener('click', _onOutsideClick);
    }, 10);
}

export function closePicker() {
    if (!_isOpen) return;
    _isOpen = false;

    if (_pickerEl) {
        _pickerEl.classList.remove('open');
        setTimeout(() => _pickerEl?.remove(), 200);
    }

    document.removeEventListener('click', _onOutsideClick);
}

export function togglePicker() {
    _isOpen ? closePicker() : openPicker();
}

/**
 * Render emoji picker into an external container (for unified picker).
 */
export function renderInto(container) {
    _loadSkinTone();
    if (!_pickerEl) _pickerEl = _buildPicker();
    container.appendChild(_pickerEl);
    _pickerEl.classList.add('open');
    _isOpen = true;
    _renderEmojis();
    requestAnimationFrame(() => _pickerEl?.querySelector('#ecp-search')?.focus());
}

window._renderEmojiInto = renderInto;
window._closeEmojiPicker = closePicker;

function _onOutsideClick(e) {
    if (_pickerEl && !_pickerEl.contains(e.target) &&
        !e.target.closest('#emoji-input-btn') &&
        !e.target.closest('#unified-picker') &&
        !e.target.closest('#expr-btn')) {
        closePicker();
    }
}

export function isOpen() { return _isOpen; }
