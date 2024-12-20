import { lazy } from 'react';
import ProtectedRoute from '../components/ProtectedRoute';
const Index = lazy(() => import('../pages/Index'));
const Analytics = lazy(() => import('../pages/Analytics'));
const Finance = lazy(() => import('../pages/Finance'));
const Crypto = lazy(() => import('../pages/Crypto'));
const Todolist = lazy(() => import('../pages/Apps/Todolist'));
const Mailbox = lazy(() => import('../pages/Apps/Mailbox'));
const Notes = lazy(() => import('../pages/Apps/Notes'));
const Contacts = lazy(() => import('../pages/Apps/Contacts'));
const Chat = lazy(() => import('../pages/Apps/Chat'));
const Scrumboard = lazy(() => import('../pages/Apps/Scrumboard'));
const Calendar = lazy(() => import('../pages/Apps/Calendar'));
const List = lazy(() => import('../pages/Apps/Invoice/List'));
const Preview = lazy(() => import('../pages/Apps/Invoice/Preview'));
const Add = lazy(() => import('../pages/Apps/Invoice/Add'));
const Edit = lazy(() => import('../pages/Apps/Invoice/Edit'));
const Tabs = lazy(() => import('../pages/Components/Tabs'));
const Accordians = lazy(() => import('../pages/Components/Accordians'));
const Modals = lazy(() => import('../pages/Components/Modals'));
const Cards = lazy(() => import('../pages/Components/Cards'));
const Carousel = lazy(() => import('../pages/Components/Carousel'));
const Countdown = lazy(() => import('../pages/Components/Countdown'));
const Counter = lazy(() => import('../pages/Components/Counter'));
const SweetAlert = lazy(() => import('../pages/Components/SweetAlert'));
const Timeline = lazy(() => import('../pages/Components/Timeline'));
const Notification = lazy(() => import('../pages/Components/Notification'));
const MediaObject = lazy(() => import('../pages/Components/MediaObject'));
const ListGroup = lazy(() => import('../pages/Components/ListGroup'));
const PricingTable = lazy(() => import('../pages/Components/PricingTable'));
const LightBox = lazy(() => import('../pages/Components/LightBox'));
const Alerts = lazy(() => import('../pages/Elements/Alerts'));
const Avatar = lazy(() => import('../pages/Elements/Avatar'));
const Badges = lazy(() => import('../pages/Elements/Badges'));
const Breadcrumbs = lazy(() => import('../pages/Elements/Breadcrumbs'));
const Buttons = lazy(() => import('../pages/Elements/Buttons'));
const Buttongroups = lazy(() => import('../pages/Elements/Buttongroups'));
const Colorlibrary = lazy(() => import('../pages/Elements/Colorlibrary'));
const DropdownPage = lazy(() => import('../pages/Elements/DropdownPage'));
const Infobox = lazy(() => import('../pages/Elements/Infobox'));
const Jumbotron = lazy(() => import('../pages/Elements/Jumbotron'));
const Loader = lazy(() => import('../pages/Elements/Loader'));
const Pagination = lazy(() => import('../pages/Elements/Pagination'));
const Popovers = lazy(() => import('../pages/Elements/Popovers'));
const Progressbar = lazy(() => import('../pages/Elements/Progressbar'));
const Search = lazy(() => import('../pages/Elements/Search'));
const Tooltip = lazy(() => import('../pages/Elements/Tooltip'));
const Treeview = lazy(() => import('../pages/Elements/Treeview'));
const Typography = lazy(() => import('../pages/Elements/Typography'));
const Widgets = lazy(() => import('../pages/Widgets'));
const FontIcons = lazy(() => import('../pages/FontIcons'));
const DragAndDrop = lazy(() => import('../pages/DragAndDrop'));
const Tables = lazy(() => import('../pages/Tables'));
const Basic = lazy(() => import('../pages/DataTables/Basic'));
const Advanced = lazy(() => import('../pages/DataTables/Advanced'));
const Skin = lazy(() => import('../pages/DataTables/Skin'));
const OrderSorting = lazy(() => import('../pages/DataTables/OrderSorting'));
const MultiColumn = lazy(() => import('../pages/DataTables/MultiColumn'));
const MultipleTables = lazy(() => import('../pages/DataTables/MultipleTables'));
const AltPagination = lazy(() => import('../pages/DataTables/AltPagination'));
const Checkbox = lazy(() => import('../pages/DataTables/Checkbox'));
const RangeSearch = lazy(() => import('../pages/DataTables/RangeSearch'));
const Export = lazy(() => import('../pages/DataTables/Export'));
const ColumnChooser = lazy(() => import('../pages/DataTables/ColumnChooser'));
const Profile = lazy(() => import('../pages/Users/Profile'));
const AccountSetting = lazy(() => import('../pages/Users/AccountSetting'));
const KnowledgeBase = lazy(() => import('../pages/Pages/KnowledgeBase'));
const ContactUsBoxed = lazy(() => import('../pages/Pages/ContactUsBoxed'));
const ContactUsCover = lazy(() => import('../pages/Pages/ContactUsCover'));
const Faq = lazy(() => import('../pages/Pages/Faq'));
const ComingSoonBoxed = lazy(() => import('../pages/Pages/ComingSoonBoxed'));
const ComingSoonCover = lazy(() => import('../pages/Pages/ComingSoonCover'));
const ERROR404 = lazy(() => import('../pages/Pages/Error404'));
const ERROR500 = lazy(() => import('../pages/Pages/Error500'));
const ERROR503 = lazy(() => import('../pages/Pages/Error503'));
const Maintenence = lazy(() => import('../pages/Pages/Maintenence'));
const LoginBoxed = lazy(() => import('../pages/Authentication/LoginBoxed'));
const RegisterBoxed = lazy(() => import('../pages/Authentication/RegisterBoxed'));
const UnlockBoxed = lazy(() => import('../pages/Authentication/UnlockBox'));
const RecoverIdBoxed = lazy(() => import('../pages/Authentication/RecoverIdBox'));
const LoginCover = lazy(() => import('../pages/Authentication/LoginCover'));
const RegisterCover = lazy(() => import('../pages/Authentication/RegisterCover'));
const RecoverIdCover = lazy(() => import('../pages/Authentication/RecoverIdCover'));
const UnlockCover = lazy(() => import('../pages/Authentication/UnlockCover'));
const About = lazy(() => import('../pages/About'));
const Error = lazy(() => import('../components/Error'));
const Charts = lazy(() => import('../pages/Charts'));
const FormBasic = lazy(() => import('../pages/Forms/Basic'));
const FormInputGroup = lazy(() => import('../pages/Forms/InputGroup'));
const FormLayouts = lazy(() => import('../pages/Forms/Layouts'));
const Validation = lazy(() => import('../pages/Forms/Validation'));
const InputMask = lazy(() => import('../pages/Forms/InputMask'));
const Select2 = lazy(() => import('../pages/Forms/Select2'));
const Touchspin = lazy(() => import('../pages/Forms/TouchSpin'));
const CheckBoxRadio = lazy(() => import('../pages/Forms/CheckboxRadio'));
const Switches = lazy(() => import('../pages/Forms/Switches'));
const Wizards = lazy(() => import('../pages/Forms/Wizards'));
const FileUploadPreview = lazy(() => import('../pages/Forms/FileUploadPreview'));
const QuillEditor = lazy(() => import('../pages/Forms/QuillEditor'));
const MarkDownEditor = lazy(() => import('../pages/Forms/MarkDownEditor'));
const DateRangePicker = lazy(() => import('../pages/Forms/DateRangePicker'));
const Clipboard = lazy(() => import('../pages/Forms/Clipboard'));


const routes = [
    // dashboard
    {
        path: '/',
        element: <Index />,
        // element: (
        //     <ProtectedRoute allowedRoles={['admin']}>
        //         <Index />
        //     </ProtectedRoute>
        // ),
    },
    // {
    //     path: '/index',
    //     element: <Index />,
    // },
    // analytics page
    {
        path: '/analytics',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <Analytics />
            </ProtectedRoute>
        ),
    },
    // finance page
    {
        path: '/finance',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <Finance />
            </ProtectedRoute>
        ),
    },
    // crypto page
    {
        path: '/crypto',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <Crypto />
            </ProtectedRoute>
        ),
    },
    {
        path: '/apps/todolist',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <Todolist />
            </ProtectedRoute>
        ),
    },
    {
        path: '/apps/notes',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <Notes />
            </ProtectedRoute>
        ),
    },
    {
        path: '/apps/contacts',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <Contacts />
            </ProtectedRoute>
        ),
    },
    {
        path: '/apps/mailbox',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <Mailbox />
            </ProtectedRoute>
        ),
    },
    {
        path: '/apps/invoice/list',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <List />
            </ProtectedRoute>
        ),
    },
    // Apps page
    {
        path: '/apps/chat',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <Chat />
            </ProtectedRoute>
        ),
    },
    {
        path: '/apps/scrumboard',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <Scrumboard />
            </ProtectedRoute>
        ),
    },
    {
        path: '/apps/calendar',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <Calendar />
            </ProtectedRoute>
        ),
    },
    // preview page
    {
        path: '/apps/invoice/preview',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <Preview />
            </ProtectedRoute>
        ),
    },
    {
        path: '/apps/invoice/add',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <Add />
            </ProtectedRoute>
        ),
    },
    {
        path: '/apps/invoice/edit',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <Edit />
            </ProtectedRoute>
        ),
    },
    // components page
    {
        path: '/components/tabs',
        element: <Tabs />,
    },
    {
        path: '/components/accordions',
        element: <Accordians />,
    },
    {
        path: '/components/modals',
        element: <Modals />,
    },
    {
        path: '/components/cards',
        element: <Cards />,
    },
    {
        path: '/components/carousel',
        element: <Carousel />,
    },
    {
        path: '/components/countdown',
        element: <Countdown />,
    },
    {
        path: '/components/counter',
        element: <Counter />,
    },
    {
        path: '/components/sweetalert',
        element: <SweetAlert />,
    },
    {
        path: '/components/timeline',
        element: <Timeline />,
    },
    {
        path: '/components/notifications',
        element: <Notification />,
    },
    {
        path: '/components/media-object',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <MediaObject />
            </ProtectedRoute>
        ),
    },
    {
        path: '/components/list-group',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <ListGroup />
            </ProtectedRoute>
        ),
    },
    {
        path: '/components/pricing-table',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <PricingTable />
            </ProtectedRoute>
        ),
    },
    {
        path: '/components/lightbox',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <LightBox />
            </ProtectedRoute>
        ),
    },
    // elements page
    {
        path: '/elements/alerts',
        element: <Alerts />,
    },
    {
        path: '/elements/avatar',
        element: <Avatar />,
    },
    {
        path: '/elements/badges',
        element: <Badges />,
    },
    {
        path: '/elements/breadcrumbs',
        element: <Breadcrumbs />,
    },
    {
        path: '/elements/buttons',
        element: <Buttons />,
    },
    {
        path: '/elements/buttons-group',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <Buttongroups />
            </ProtectedRoute>
        ),
    },
    {
        path: '/elements/color-library',
        element: <Colorlibrary />,
    },
    {
        path: '/elements/dropdown',
        element: <DropdownPage />,
    },
    {
        path: '/elements/infobox',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <Infobox />
            </ProtectedRoute>
        ),
    },
    {
        path: '/elements/jumbotron',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <Jumbotron />
            </ProtectedRoute>
        ),
    },
    {
        path: '/elements/loader',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <Loader />
            </ProtectedRoute>
        ),
    },
    {
        path: '/elements/pagination',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <Pagination />
            </ProtectedRoute>
        ),
    },
    {
        path: '/elements/popovers',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <Popovers />
            </ProtectedRoute>
        ),
    },
    {
        path: '/elements/progress-bar',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <Progressbar />
            </ProtectedRoute>
        ),
    },
    {
        path: '/elements/search',
        element: <Search />,
    },
    {
        path: '/elements/tooltips',
        element: <Tooltip />,
    },
    {
        path: '/elements/treeview',
        element: <Treeview />,
    },
    {
        path: '/elements/typography',
        element: <Typography />,
    },

    // charts page
    {
        path: '/charts',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <Charts />
            </ProtectedRoute>
        ),
    },
    // widgets page
    {
        path: '/widgets',
        element: <Widgets />,
    },
    //  font-icons page
    {
        path: '/font-icons',
        element: <FontIcons />,
    },
    //  Drag And Drop page
    {
        path: '/dragndrop',
        element: <DragAndDrop />,
    },
    //  Tables page
    {
        path: '/tables',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <Tables />
            </ProtectedRoute>
        ),
    },
    // Data Tables
    {
        path: '/datatables/basic',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <Basic />
            </ProtectedRoute>
        ),
    },
    {
        path: '/datatables/advanced',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <Advanced />
            </ProtectedRoute>
        ),
    },
    {
        path: '/datatables/skin',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <Skin />
            </ProtectedRoute>
        ),
    },
    {
        path: '/datatables/order-sorting',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <OrderSorting />
            </ProtectedRoute>
        ),
    },
    {
        path: '/datatables/multi-column',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <MultiColumn />
            </ProtectedRoute>
        ),
    },
    {
        path: '/datatables/multiple-tables',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <MultipleTables />
            </ProtectedRoute>
        ),
    },
    {
        path: '/datatables/alt-pagination',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <AltPagination />
            </ProtectedRoute>
        ),
    },
    {
        path: '/datatables/checkbox',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <Checkbox />
            </ProtectedRoute>
        ),
    },
    {
        path: '/datatables/range-search',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <RangeSearch />
            </ProtectedRoute>
        ),
    },
    {
        path: '/datatables/export',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <Export />
            </ProtectedRoute>
        ),
    },
    {
        path: '/datatables/column-chooser',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <ColumnChooser />
            </ProtectedRoute>
        ),
    },
    // Users page
    {
        path: '/users/profile',
        element: <Profile />,
    },
    {
        path: '/users/user-account-settings',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <AccountSetting />
            </ProtectedRoute>
        ),
    },
    // pages
    {
        path: '/pages/knowledge-base',
        element: (
            <ProtectedRoute allowedRoles={['admin']}>
                <KnowledgeBase />
            </ProtectedRoute>
        ),
    },
    {
        path: '/pages/contact-us-boxed',
        element: <ContactUsBoxed />,
        layout: 'blank',
    },
    {
        path: '/pages/contact-us-cover',
        element: <ContactUsCover />,
        layout: 'blank',
    },
    {
        path: '/pages/faq',
        element: <Faq />,
    },
    {
        path: '/pages/coming-soon-boxed',
        element: <ComingSoonBoxed />,
        layout: 'blank',
    },
    {
        path: '/pages/coming-soon-cover',
        element: <ComingSoonCover />,
        layout: 'blank',
    },
    {
        path: '/pages/error404',
        element: <ERROR404 />,
        layout: 'blank',
    },
    {
        path: '/pages/error500',
        element: <ERROR500 />,
        layout: 'blank',
    },
    {
        path: '/pages/error503',
        element: <ERROR503 />,
        layout: 'blank',
    },
    {
        path: '/pages/maintenence',
        element: <Maintenence />,
        layout: 'blank',
    },
    //Authentication
    {
        path: '/auth/boxed-signin',
        element: <LoginBoxed />,
        layout: 'blank',
    },
    {
        path: '/auth/boxed-signup',
        element: <RegisterBoxed />,
        layout: 'blank',
    },
    {
        path: '/auth/boxed-lockscreen',
        element: <UnlockBoxed />,
        layout: 'blank',
    },
    {
        path: '/auth/boxed-password-reset',
        element: <RecoverIdBoxed />,
        layout: 'blank',
    },
    {
        path: '/auth/cover-login',
        element: <LoginCover />,
        layout: 'blank',
    },
    {
        path: '/auth/cover-register',
        element: <RegisterCover />,
        layout: 'blank',
    },
    {
        path: '/auth/cover-lockscreen',
        element: <UnlockCover />,
        layout: 'blank',
    },
    {
        path: '/auth/cover-password-reset',
        element: <RecoverIdCover />,
        layout: 'blank',
    },
    //forms page
    {
        path: '/forms/basic',
        element: <FormBasic />,
    },
    {
        path: '/forms/input-group',
        element: <FormInputGroup />,
    },
    {
        path: '/forms/layouts',
        element: <FormLayouts />,
    },
    {
        path: '/forms/validation',
        element: <Validation />,
    },
    {
        path: '/forms/input-mask',
        element: <InputMask />,
    },
    {
        path: '/forms/select2',
        element: <Select2 />,
    },
    {
        path: '/forms/touchspin',
        element: <Touchspin />,
    },
    {
        path: '/forms/checkbox-radio',
        element: <CheckBoxRadio />,
    },
    {
        path: '/forms/switches',
        element: <Switches />,
    },
    {
        path: '/forms/wizards',
        element: <Wizards />,
    },
    {
        path: '/forms/file-upload',
        element: <FileUploadPreview />,
    },
    {
        path: '/forms/quill-editor',
        element: <QuillEditor />,
    },
    {
        path: '/forms/markdown-editor',
        element: <MarkDownEditor />,
    },
    {
        path: '/forms/date-picker',
        element: <DateRangePicker />,
    },
    {
        path: '/forms/clipboard',
        element: <Clipboard />,
    },
    {
        path: '/about',
        element: <About />,
        layout: 'blank',
    },
    {
        path: '*',
        element: <Error />,
        layout: 'blank',
    },
];

export { routes };




// const routes = [
//     {
//         path: '*',
//         element: <div>Fallback Route</div>,
//     },
// ];

// export { routes };